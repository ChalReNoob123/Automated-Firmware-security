'use client';
import { useEffect, useState } from 'react';
import { armFromPreference, audioPreferred, disableAudio, enableAudio, isAudioOn, subscribeAudio } from './sfx';

// SF://AUDIO nav chip — the switch for the site's synthesized robotic
// soundscape, which is ON BY DEFAULT since round 28 (browsers still gate the
// AudioContext behind a gesture, so the chip reads ARMED and the very first
// pointer-down/keydown anywhere arms the engine quietly — no stealth boot
// fanfare). Clicking the chip plays the full boot fanfare; muting persists
// (sf_audio=0) across visits. While ON, four EQ bars dance (pure CSS,
// reduced-motion gated).

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
          ? 'Interface audio is ON — synthesized live, no downloads. Click to mute (remembered).'
          : armed
            ? 'Sound arms itself on your first click or keypress (browser rule). Click now to enable with the boot fanfare, or to mute permanently.'
            : 'Sound is muted by your choice. Click to enable the SentinelForge soundscape.'
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
