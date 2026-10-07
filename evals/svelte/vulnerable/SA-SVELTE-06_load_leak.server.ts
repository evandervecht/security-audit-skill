import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ params }) => {
  const user = await db.user.findUnique({ where: { id: params.id } });
  return {
    user,
    passwordHash: user.passwordHash,
    apiToken: user.apiToken
  };
};
