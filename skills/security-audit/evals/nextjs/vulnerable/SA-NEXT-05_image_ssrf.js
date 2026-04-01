// SA-NEXT-05: Wildcard hostname in next/image config — SSRF risk
/** @type {import('next').NextConfig} */
module.exports = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: '**' },
    ],
  },
};
