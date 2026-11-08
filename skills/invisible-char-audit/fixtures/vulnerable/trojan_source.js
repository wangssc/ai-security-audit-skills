// access control
function check(user) {
  if (user.role !== "admin" ‮ ) { return false; } ‭ // admin path
  return true;
}
module.exports = check;
