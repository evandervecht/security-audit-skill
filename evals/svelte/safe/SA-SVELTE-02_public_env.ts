import { PUBLIC_STRIPE_KEY } from '$env/static/public';
import { env } from '$env/dynamic/public';

export function getPublishableKey() {
  return PUBLIC_STRIPE_KEY ?? env.PUBLIC_API_URL;
}
