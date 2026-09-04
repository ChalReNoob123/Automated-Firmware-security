import AmbientScene from '../AmbientScene';
import AuthForm from '../auth/AuthForm';

export default function LoginPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 560 }}>
        <p className="sf-eyebrow">SENTINELFORGE v3 · SIGN IN</p>
        <h1 className="sf-h1 sf-gradient-text">Back to the bench.</h1>
        <div style={{ marginTop: 8 }}>
          <AuthForm mode="login" />
        </div>
      </main>
    </>
  );
}
