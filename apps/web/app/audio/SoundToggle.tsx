'use client';
import { useEffect, useState } from 'react';
import { armFromPreference, audioPreferred, disableAudio, enableAudio, isAudioOn, subscribeAudio } from './sfx';

// SF://AUDIO nav chip — the opt-in switch for the site's synthesized robotic
// soundscape. OFF by default (autoplay policies + basic politeness); the click
// is the user gesture that arms the AudioContext. While ON, four EQ bars dance
// (pure CSS, reduced-motion gated). If the preference was left ON in a previous
// session, the chip shows ARMED and the very next pointer-down anywhere
// re-activates the engine quietly — no stealth boot fanfare.

export default function SoundToggle() {
  const [on, setOn] = useState(false);
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    setOn(isAudioOn());
    const un = subscribeAudio(setOn);
    if (audioPreferred() && !isAudioOn()) {
      setArmed(true);
      armFromPreference();
    }
    return un;
  }, []);

  const toggle = () => {
    if (isAudioOn()) disableAudio();
    else enableAudio();
    setArmed(false);
  };

  const label = on ? 'SF://AUDIO ON' : armed ? 'SF://AUDIO ARMED' : 'SF://AUDIO OFF';
  return (
    <button
      className={`sf-audio-chip${on ? ' on' : ''}`}
      onClick={toggle}
      aria-pressed={on}
      title={
        on
          ? 'Interface audio is ON — synthesized live, no downloads. Click to mute.'
          : 'Enable the SentinelForge robotic soundscape — synthesized live in your browser. Opt-in.'
      }
    >
      <span className="sf-eq" aria-hidden>
        <i />
        <i />
        <i />
        <i />
      </span>
      {label}
    </button>
  );
}
