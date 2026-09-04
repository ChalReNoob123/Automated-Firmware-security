import AmbientScene from '../AmbientScene';
import AuthForm from '../auth/AuthForm';

export default function SignupPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 560 }}>
        <p className="sf-eyebrow">SENTINELFORGE v3 · GET STARTED</p>
        <h1 className="sf-h1 sf-gradient-text">Claim your workspace.</h1>
        <div style={{ marginTop: 8 }}>
          <AuthForm mode="signup" />
        </div>
      </main>
    </>
  );
}
