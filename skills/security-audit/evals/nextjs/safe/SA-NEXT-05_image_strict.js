// SA-NEXT-05: Safe — strict hostname allowlist for next/image
/** @type {import('next').NextConfig} */
module.exports = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'images.mycdn.com', pathname: '/uploads/**' },
      { protocol: 'https', hostname: 'avatars.githubusercontent.com' },
    ],
  },
};
