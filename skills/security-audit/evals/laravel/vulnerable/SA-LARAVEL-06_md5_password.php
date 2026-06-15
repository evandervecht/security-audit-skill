<?php
// SA-LARAVEL-06: weak password hashing with md5
class AuthController
{
    public function register(Request $request): void
    {
        $user = new User();
        $user->password = md5($request->password);
        $user->save();
    }
}
