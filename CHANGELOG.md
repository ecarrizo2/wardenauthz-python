# Changelog

## Unreleased

- `team_members.resend_invite()` — resend a pending invitation's email (at most 5 sends, 10 minutes apart)
- `TeamMemberItem` — `email`, `status`, `role_ids` and, for pending invitations, `invite_sent_at`,
  `invite_send_count`, `invite_email_failed`
- Invitations are no longer accepted automatically at sign-in; the invitee accepts them in the dashboard
- The bulk audit export endpoint is temporarily disabled and answers `503`

## 0.2.0

- Initial public release
- Full API coverage for all resources
- Comprehensive test suite
- CI/CD with GitHub Actions

## 0.1.0

- Initial development release
