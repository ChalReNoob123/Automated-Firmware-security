import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import ArtPanel from '../ArtPanel';
import AuthForm from '../auth/AuthForm';

// Split-screen auth: the form on one side, a living fluid aurora panel on the
// other (≥980px). Below that the art panel stacks beneath the form.
export default function LoginPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page sf-auth-split">
        <div>
          <PageHeader eyebrow="SENTINELFORGE v3 · SIGN IN" title="Back to the bench." />
          <div style={{ marginTop: 8 }}>
            <AuthForm mode="login" />
          </div>
        </div>
        <ArtPanel variant="fluid" height={420} className="sf-auth-art">
          <div className="sf-caption-eyebrow">OPERATIONS CONSOLE</div>
          <div className="sf-caption-title">Your session, your tenancy</div>
          <div className="sf-caption-sub">
            Memory-held access tokens, HttpOnly refresh, TOTP step-up — the console lights up only for you.
          </div>
        </ArtPanel>
      </main>
    </>
  );
}
