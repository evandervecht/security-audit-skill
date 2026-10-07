// SA-NUXT-01: Safe — handler with auth check (not matching async (event) arrow pattern)
export default defineEventHandler(async function listUsers(evt) {
  const session = await getUserSession(evt);
  if (!session?.user) {
    throw createError({ statusCode: 401, message: 'Unauthorized' });
  }
  return await db.user.findMany({
    select: { id: true, name: true, email: true },
  });
});
