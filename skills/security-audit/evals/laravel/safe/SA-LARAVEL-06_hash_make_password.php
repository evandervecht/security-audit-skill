<?php
// SA-LARAVEL-06: bcrypt via Hash::make
class AuthController
{
    public function register(Request $request): void
    {
        $user = new User();
        $user->password = Hash::make($request->password);
        $user->save();
    }
}
