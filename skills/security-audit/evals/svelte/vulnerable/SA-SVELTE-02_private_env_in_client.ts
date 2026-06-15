import { STRIPE_SECRET_KEY } from '$env/static/private';

export function createCharge(amount) {
  return fetch('https://api.stripe.com/v1/charges', {
    headers: { Authorization: `Bearer ${STRIPE_SECRET_KEY}` },
    method: 'POST',
  });
}
