const { PHASE_PRODUCTION_BUILD } = require('next/constants');

/** @type {(phase: string) => import('next').NextConfig} */
module.exports = (phase) => {
  // Refuse to start without a session secret rather than failing on the first sign-in.
  // `next build` loads this file too but never signs a session, so it needs none.
  if (phase !== PHASE_PRODUCTION_BUILD && !process.env.NEXTAUTH_SECRET) {
    throw new Error('NEXTAUTH_SECRET is required');
  }
  return {};
};
