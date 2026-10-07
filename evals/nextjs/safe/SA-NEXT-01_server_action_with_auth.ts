// SA-NEXT-01: Safe — server-side handler with auth check
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

async function handleDeleteUser(userId: string) {
  const session = await auth();
  if (!session?.user || session.user.role !== 'admin') {
    throw new Error('Forbidden');
  }
  await db.user.delete({ where: { id: userId } });
  return { success: true };
}
