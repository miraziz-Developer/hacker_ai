from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import httpx

from hacker_ai.ai import AnalysisError, AzureAnalyzer
from hacker_ai.config import TelegramSettings, Workspace
from hacker_ai.models import AgentPlan, FindingDraft, ScopeDocument
from hacker_ai.recon import ReconError, recon_target, run_nmap, run_subfinder
from hacker_ai.redaction import redact_secrets
from hacker_ai.scope import ScopeError, check_scope, load_scope
from hacker_ai.storage import Storage


class TelegramError(RuntimeError):
    """Raised when Telegram transport or message data is invalid."""


@dataclass(frozen=True)
class PendingAction:
    plan: AgentPlan
    chat_id: int


class TelegramClient:
    def __init__(self, settings: TelegramSettings) -> None:
        self.settings = settings
        self.base_url = f"https://api.telegram.org/bot{settings.token}"
        self.client = httpx.Client(timeout=settings.poll_timeout_seconds + 10)

    def get_updates(self, offset: int | None = None) -> list[dict[str, Any]]:
        params: dict[str, int] = {"timeout": self.settings.poll_timeout_seconds}
        if offset is not None:
            params["offset"] = offset
        result = self._request("getUpdates", params).get("result", [])
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise TelegramError("Telegram API returned malformed updates")
        return cast(list[dict[str, Any]], result)

    def send_message(self, chat_id: int, text: str) -> None:
        self._request("sendMessage", {"chat_id": chat_id, "text": text[:4096]})

    def _request(self, method: str, data: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.client.post(f"{self.base_url}/{method}", json=data)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise TelegramError(f"Telegram API request failed: {type(exc).__name__}") from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise TelegramError("Telegram API rejected the request")
        return payload


class TelegramAgent:
    def __init__(
        self,
        workspace: Workspace,
        storage: Storage,
        planner: Callable[[str], AgentPlan],
        settings: TelegramSettings | None = None,
        analyzer: Callable[[str, str, ScopeDocument], FindingDraft] | None = None,
    ) -> None:
        self.workspace = workspace
        self.storage = storage
        self.planner = planner
        self.settings = settings
        self.analyzer = analyzer
        self.pending: dict[int, PendingAction] = {}

    def handle(self, user_id: int, chat_id: int, text: str) -> str:
        safe_text = redact_secrets(text.strip())
        self.storage.audit(
            "telegram.request", allowed=True, details={"user_id": user_id, "length": len(text)}
        )
        if safe_text.lower() in {"/cancel", "cancel", "bekor"}:
            self.pending.pop(user_id, None)
            self.storage.audit("telegram.cancel", allowed=True, details={"user_id": user_id})
            return "Bekor qilindi."
        if safe_text.lower() in {"/confirm", "confirm", "tasdiqlayman"}:
            return self._confirm(user_id, chat_id)
        if safe_text.lower() in {"/start", "/help"}:
            return self._help()
        plan = self.planner(safe_text)
        self.storage.audit(
            "telegram.plan",
            target=plan.target,
            allowed=True,
            details={"user_id": user_id, "action": plan.action},
        )
        if plan.action == "help":
            return f"{plan.explanation}\n\n{self._help()}"
        if plan.action == "status":
            document = load_scope(self.workspace.scope_file)
            return (
                f"Workspace: {self.workspace.root}\nProgram: {document.program.name}\n"
                f"{self._capability_status()}"
            )
        if not plan.target:
            return "Aniq target ko‘rsatilmagan. Domen, IP yoki HTTP(S) URL yuboring."
        document = load_scope(self.workspace.scope_file)
        decision = check_scope(document, plan.target)
        if not decision.allowed:
            self.storage.audit(
                "telegram.action.denied",
                target=plan.target,
                allowed=False,
                details={"user_id": user_id, "reason": decision.reason},
            )
            return f"RAD ETILDI: {decision.reason}"
        if plan.action == "scope_check":
            return f"RUXSAT: {decision.reason}"
        capability_denial = self._capability_denial(plan.action)
        if capability_denial:
            self.storage.audit(
                "telegram.capability.denied",
                target=plan.target,
                allowed=False,
                details={"user_id": user_id, "action": plan.action},
            )
            return capability_denial
        self.pending[user_id] = PendingAction(plan, chat_id)
        return (
            f"Reja: {plan.explanation}\nTarget: {plan.target}\n"
            "Network amali hali bajarilmadi. /confirm yuboring yoki /cancel bilan bekor qiling."
        )

    def _confirm(self, user_id: int, chat_id: int) -> str:
        pending = self.pending.get(user_id)
        if pending is None or pending.chat_id != chat_id:
            return "Tasdiqlash uchun kutilayotgan amal yo‘q."
        self.pending.pop(user_id)
        plan = pending.plan
        assert plan.target is not None
        capability_denial = self._capability_denial(plan.action)
        if capability_denial:
            self.storage.audit(
                "telegram.capability.denied",
                target=plan.target,
                allowed=False,
                details={"user_id": user_id, "action": plan.action},
            )
            return capability_denial
        document = load_scope(self.workspace.scope_file)
        decision = check_scope(document, plan.target)
        if not decision.allowed:
            self.storage.audit(
                "telegram.execute.denied",
                target=plan.target,
                allowed=False,
                details={"user_id": user_id, "reason": decision.reason},
            )
            return f"RAD ETILDI: {decision.reason}"
        try:
            if plan.action == "recon_http":
                payload = recon_target(document, plan.target).model_dump(mode="json")
            elif plan.action == "recon_subdomains":
                payload = run_subfinder(document, plan.target).model_dump(mode="json")
            elif plan.action == "recon_ports":
                payload = run_nmap(document, plan.target, plan.ports or "80,443").model_dump(
                    mode="json"
                )
            elif plan.action == "assess_web":
                if self.analyzer is None:
                    raise TelegramError("Web assessment analyzer is not configured")
                recon = recon_target(document, plan.target)
                evidence = json.dumps(recon.model_dump(mode="json"), ensure_ascii=False)
                finding = self.analyzer(plan.target, evidence, document)
                finding_id = self.storage.save_finding(
                    plan.target, finding.model_dump(mode="json")
                )
                self.storage.audit(
                    "telegram.execute",
                    target=plan.target,
                    allowed=True,
                    details={"user_id": user_id, "action": plan.action},
                )
                return self._format_finding(finding_id, plan.target, finding)
            else:
                raise TelegramError("Pending action is not executable")
            self.storage.audit(
                "telegram.execute",
                target=plan.target,
                allowed=True,
                details={"user_id": user_id, "action": plan.action},
            )
            return json.dumps(payload, ensure_ascii=False, indent=2)
        except (AnalysisError, ReconError, ScopeError, TelegramError, ValueError) as exc:
            self.storage.audit(
                "telegram.execute.denied",
                target=plan.target,
                allowed=False,
                details={"user_id": user_id, "reason": redact_secrets(str(exc))},
            )
            return f"Bajarilmadi: {redact_secrets(str(exc))}"

    def _capability_denial(self, action: str) -> str | None:
        if self.settings is None:
            return None
        switches = {
            "assess_web": (
                self.settings.allow_http_recon,
                "HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON",
            ),
            "recon_http": (
                self.settings.allow_http_recon,
                "HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON",
            ),
            "recon_subdomains": (
                self.settings.allow_subdomain_recon,
                "HACKER_AI_TELEGRAM_ALLOW_SUBDOMAIN_RECON",
            ),
            "recon_ports": (
                self.settings.allow_port_recon,
                "HACKER_AI_TELEGRAM_ALLOW_PORT_RECON",
            ),
        }
        capability = switches.get(action)
        if capability is not None and not capability[0]:
            return f"Bu capability o‘chirilgan: {capability[1]}=false"
        return None

    def _capability_status(self) -> str:
        if self.settings is None:
            return "Telegram capabilities: test configuration"
        return (
            "Telegram capabilities: "
            f"http={str(self.settings.allow_http_recon).lower()}, "
            f"subdomains={str(self.settings.allow_subdomain_recon).lower()}, "
            f"ports={str(self.settings.allow_port_recon).lower()}"
        )

    @staticmethod
    def _format_finding(finding_id: int, target: str, finding: FindingDraft) -> str:
        evidence = "\n".join(f"• {item}" for item in finding.evidence)
        return redact_secrets(
            f"ASSESSMENT #{finding_id}\n"
            f"Target: {target}\n"
            f"Daraja: {finding.severity.upper()} | Ishonch: {finding.confidence}\n\n"
            f"{finding.title}\n{finding.summary}\n\n"
            f"Evidence:\n{evidence}\n\n"
            f"Ta’sir:\n{finding.impact}\n\n"
            f"Himoya tavsiyasi:\n{finding.remediation}\n\n"
            "Holat: inson tekshiruvi talab qilinadi; bu finding hali ekspluatatsiya isboti emas."
        )

    @staticmethod
    def _help() -> str:
        return (
            "Menga oddiy tilda target scope’ini tekshirish, holat, HTTP recon, subdomain qidirish, "
            "cheklangan port inventarizatsiyasi yoki web assessment so‘rang. Assessment real "
            "evidence asosida zaif tomonlar va himoya tavsiyalarini ko‘rsatadi. Har bir network "
            "amali alohida /confirm talab qiladi."
        )


def run_bot(
    settings: TelegramSettings,
    workspace: Workspace,
    analyzer: AzureAnalyzer,
    client: TelegramClient | None = None,
) -> None:
    storage = Storage(workspace.database)
    storage.initialize()
    transport = client or TelegramClient(settings)
    agent = TelegramAgent(workspace, storage, analyzer.plan, settings, analyzer.analyze)
    offset: int | None = None
    while True:
        for update in transport.get_updates(offset):
            update_id = update.get("update_id")
            if isinstance(update_id, int):
                offset = update_id + 1
            message = update.get("message")
            if not isinstance(message, dict):
                continue
            sender = message.get("from")
            chat = message.get("chat")
            text = message.get("text")
            if (
                not isinstance(sender, dict)
                or not isinstance(chat, dict)
                or not isinstance(text, str)
            ):
                continue
            user_id, chat_id = sender.get("id"), chat.get("id")
            if not isinstance(user_id, int) or not isinstance(chat_id, int):
                continue
            if user_id not in settings.allowed_user_ids:
                storage.audit("telegram.unauthorized", allowed=False, details={"user_id": user_id})
                continue
            try:
                reply = agent.handle(user_id, chat_id, text)
            except (AnalysisError, ScopeError, TelegramError, OSError, ValueError) as exc:
                reply = f"Xato: {redact_secrets(str(exc))}"
            transport.send_message(chat_id, reply)
