import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ params }) => {
  const user = await db.user.findUnique({
    where: { id: params.id },
    select: { id: true, name: true, avatarUrl: true }
  });
  // passwordHash and apiToken are intentionally excluded from the returned DTO
  return { user };
};
