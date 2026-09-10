"""Politique d'autorisation outil par outil de la passerelle GitHub.

La securite ne repose ni sur une heuristique de nom, ni sur la seule disparition
d'un outil de `tools/list` : chaque outil expose par l'upstream officiel
`github/github-mcp-server` est classe explicitement ci-dessous. Tout outil absent
de cette classification est INCONNU : jamais annonce dans `tools/list`, jamais
executable (fail-closed) tant qu'un mainteneur ne l'a pas classe et deploye. Cela
empeche une future version de l'upstream d'exposer silencieusement un outil
dangereux.

Profil : surface maximale RW voulue par Titou (`GITHUB_TOOLSETS=all`, mode
read-only DESACTIVE). 59 outils de lecture + 35 mutateurs (v1.12.0, 94 tools),
soit l'integralite du catalogue local officiel. Aucun outil n'est bloque en
`admin` : `delete_repository` (gate MRTR cote upstream) reste accessible avec la
portee ecriture, les protections natives GitHub (branch protection, rulesets,
permissions du compte) continuant de s'appliquer.

Classification etablie depuis le README upstream v1.12.0 (2026-09-03) :
- lecture : get_*, list_*, search_*, *_read, custom_properties_read,
  repository_ruleset_read, github_support_docs_search, get_me, get_teams...
- ecriture : create_*, update_*, delete_*, merge_*, push_*, *_write,
  actions_run_trigger, assign_*, request_*, fork/star/unstar, dismiss_*,
  manage_*_subscription, mark_all_notifications_read.
"""

from __future__ import annotations

from dataclasses import dataclass

from github_gateway.oauth import PORTEE, PORTEE_ECRITURE

# Lecture seule : aucune donnee GitHub n'est modifiee (59 outils, v1.12.0).
OUTILS_LECTURE: frozenset[str] = frozenset(
    {
        "actions_get",
        "actions_list",
        "custom_properties_read",
        "get_code_quality_finding",
        "get_code_scanning_alert",
        "get_commit",
        "get_copilot_space",
        "get_dependabot_alert",
        "get_discussion",
        "get_discussion_comments",
        "get_file_contents",
        "get_gist",
        "get_global_security_advisory",
        "get_job_logs",
        "get_label",
        "get_latest_release",
        "get_me",
        "get_notification_details",
        "get_release_by_tag",
        "get_repository_tree",
        "get_secret_scanning_alert",
        "get_tag",
        "get_team_members",
        "get_teams",
        "github_support_docs_search",
        "issue_read",
        "list_branches",
        "list_code_scanning_alerts",
        "list_commits",
        "list_copilot_spaces",
        "list_dependabot_alerts",
        "list_discussion_categories",
        "list_discussions",
        "list_gists",
        "list_global_security_advisories",
        "list_issue_fields",
        "list_issue_types",
        "list_issues",
        "list_label",
        "list_notifications",
        "list_org_repository_security_advisories",
        "list_pull_requests",
        "list_releases",
        "list_repository_collaborators",
        "list_repository_security_advisories",
        "list_secret_scanning_alerts",
        "list_starred_repositories",
        "list_tags",
        "projects_get",
        "projects_list",
        "pull_request_read",
        "repository_ruleset_read",
        "search_code",
        "search_commits",
        "search_issues",
        "search_orgs",
        "search_pull_requests",
        "search_repositories",
        "search_users",
    }
)

# Mutateurs : creation/modification/suppression sur GitHub (35 outils, v1.12.0).
# `delete_repository` exige en plus GITHUB_MCP_SERVER_MRTR_STATE_KEY cote upstream
# (comportement officiel) ; sans cette cle l'outil est masque par l'upstream lui-meme.
OUTILS_ECRITURE: frozenset[str] = frozenset(
    {
        "actions_run_trigger",
        "add_comment_to_pending_review",
        "add_issue_comment",
        "add_reply_to_pull_request_comment",
        "assign_copilot_to_issue",
        "assign_copilot_to_issue_with_intent",
        "create_branch",
        "create_gist",
        "create_or_update_file",
        "create_pull_request",
        "create_pull_request_with_copilot",
        "create_repository",
        "create_repository_ruleset",
        "custom_properties_write",
        "delete_file",
        "delete_repository",
        "discussion_comment_write",
        "dismiss_notification",
        "fork_repository",
        "issue_write",
        "label_write",
        "manage_notification_subscription",
        "manage_repository_notification_subscription",
        "mark_all_notifications_read",
        "merge_pull_request",
        "projects_write",
        "pull_request_review_write",
        "push_files",
        "request_copilot_review",
        "star_repository",
        "sub_issue_write",
        "unstar_repository",
        "update_gist",
        "update_pull_request",
        "update_pull_request_branch",
    }
)

# Aucun outil bloque administrativement : la surface maximale RW est voulue.
# Les futurs outils upstream non classes restent fail-closed (refus + masquage).
OUTILS_ADMIN: frozenset[str] = frozenset()


@dataclass(frozen=True)
class PolitiqueOutils:
    """Regle d'acces a un outil upstream selon les portees du jeton valide.

    - outil de lecture  -> portee lecture requise ;
    - outil d'ecriture  -> portee ecriture requise ;
    - outil d'administration -> toujours refuse pour un client externe ;
    - tout autre nom (inconnu / pas encore classe) -> refuse (fail-closed),
      meme pour un jeton portant toutes les portees connues.
    """

    portee_lecture: str = PORTEE
    portee_ecriture: str = PORTEE_ECRITURE
    lecture: frozenset[str] = OUTILS_LECTURE
    ecriture: frozenset[str] = OUTILS_ECRITURE
    admin: frozenset[str] = OUTILS_ADMIN

    def connus(self) -> frozenset[str]:
        """Ensemble des outils classes (lecture + ecriture + admin)."""
        return self.lecture | self.ecriture | self.admin

    def visibles(self, portees: set[str]) -> set[str]:
        """Outils annoncables a un jeton portant `portees` (filtre de tools/list).

        Les outils d'administration et les outils inconnus ne sont jamais
        annonces, quel que soit le jeton.
        """
        if self.portee_lecture not in portees:
            # Cas theorique : le middleware exige deja la portee lecture pour
            # atteindre /mcp. Par defaut de robustesse : aucun outil annonce.
            return set()
        visibles = set(self.lecture)
        if self.portee_ecriture in portees:
            visibles |= set(self.ecriture)
        return visibles

    def autoriser_call(self, nom: str, portees: set[str]) -> str | None:
        """Raison de refus d'un `tools/call`, ou ``None`` si l'appel est autorise.

        Appelee AVANT tout envoi vers l'upstream.
        """
        if nom in self.admin:
            return "outil d'administration interdit aux clients de la passerelle"
        if nom in self.ecriture:
            if self.portee_ecriture in portees:
                return None
            return f"portee {self.portee_ecriture} requise pour cet outil"
        if nom in self.lecture:
            if self.portee_lecture in portees:
                return None
            return f"portee {self.portee_lecture} requise pour cet outil"
        return "outil inconnu ou non classe : appel refuse (fail-closed)"
