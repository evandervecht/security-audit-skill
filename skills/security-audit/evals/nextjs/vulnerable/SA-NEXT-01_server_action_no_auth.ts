// SA-NEXT-01: Server Action without auth check
'use server';

import { db } from '@/lib/db';

export async function deleteUser(userId: string) {
  await db.user.delete({ where: { id: userId } });
  return { success: true };
}
