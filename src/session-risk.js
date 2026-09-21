export function assessSessionContext({
  sessionIpHash,
  requestIpHash,
  sessionUserAgent,
  requestUserAgent
}) {
  const ipChanged = Boolean(sessionIpHash && requestIpHash && sessionIpHash !== requestIpHash);
  const userAgentChanged = Boolean(
    sessionUserAgent &&
    requestUserAgent &&
    sessionUserAgent !== requestUserAgent
  );

  let score = 0;
  if (ipChanged) score += 45;
  if (userAgentChanged) score += 35;

  return {
    suspicious: score >= 45,
    score: Math.min(score, 100),
    signals: {
      ipChanged,
      userAgentChanged
    }
  };
}

export function shouldTerminateSession(assessment) {
  return Boolean(
    assessment?.signals?.ipChanged &&
    assessment?.signals?.userAgentChanged
  );
}
