import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import ArtPanel from '../ArtPanel';
import AuthForm from '../auth/AuthForm';

// Split-screen auth (signup side): the wireframe digital-twin holo panel faces
// the enrollment form — "here is the machine you are about to command."
export default function SignupPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page sf-auth-split">
        <div>
          <PageHeader eyebrow="SENTINELFORGE v3 · GET STARTED" title="Claim your workspace." />
          <div style={{ marginTop: 8 }}>
            <AuthForm mode="signup" />
          </div>
        </div>
        <ArtPanel variant="holo" height={420} className="sf-auth-art">
          <div className="sf-caption-eyebrow">DIGITAL TWIN STANDBY</div>
          <div className="sf-caption-title">The twin awaits your first device</div>
          <div className="sf-caption-sub">
            Enroll, attest a device, and this wireframe becomes a bootable, breakable, replayable twin.
          </div>
        </ArtPanel>
      </main>
    </>
  );
}
