// SA-NUXT-01: Server route without auth check
export default defineEventHandler(async (event) => {
  const users = await db.user.findMany();
  return users;
});
