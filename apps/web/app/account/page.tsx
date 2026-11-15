import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import AccountClient from './AccountClient';

// Account Security Center — the user owns their security posture from here:
// live session inventory with per-device revocation, password rotation with
// re-auth (other sessions die, this one survives), and authenticator
// re-enrollment through the standard 2FA verify step.
export default function AccountPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ paddingTop: 90 }}>
        <PageHeader
          eyebrow="SENTINELFORGE v3 · ACCOUNT"
          title="Security center."
          sub="Every device holding a session, every key, your password — owned from one console."
        />
        <AccountClient />
      </main>
    </>
  );
}
