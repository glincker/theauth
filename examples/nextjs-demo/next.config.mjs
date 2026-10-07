/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    // Required for top-level await in route handlers (getTheAuth)
  },
};

export default nextConfig;
