<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Auth\Auth;
use FT\Auth\Passwords;
use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\Csrf;

/**
 * Sign-in endpoints (/api/v1/auth/*).
 *
 * login, 2fa, password/forgot and password/reset are CSRF-exempt by necessity (there is no
 * session token yet for API clients), so each of them checks that a browser request really
 * comes from our own origin (Csrf::assertSameOrigin) — this blocks "login CSRF".
 */
final class AuthController
{
    /** POST /auth/login {username,password,remember?,totp_code?,recovery_code?,issue_token?,token_name?} */
    public function login(Request $req): Response
    {
        Csrf::assertSameOrigin($req);
        $username = $req->string('username', '', 191);
        $password = $req->input('password');
        $password = is_string($password) ? $password : '';
        $errors = array_filter([
            'username' => $username === '' ? 'Enter your username.' : null,
            'password' => $password === '' ? 'Enter your password.' : (strlen($password) > 4096 ? 'This password is too long.' : null),
        ]);
        if ($errors !== []) {
            throw ApiException::validation($errors);
        }
        $result = Auth::signIn(
            $req,
            $username,
            $password,
            $req->bool('remember'),
            $this->code($req, 'totp_code') ?? $this->code($req, 'code'),
            $this->code($req, 'recovery_code'),
            $req->bool('issue_token'),
            $req->string('token_name', '', 100)
        );
        return Response::ok($this->payload($result));
    }

    /** POST /auth/2fa {challenge, code?|recovery_code?, remember?} */
    public function twoFactor(Request $req): Response
    {
        Csrf::assertSameOrigin($req);
        $challenge = $req->string('challenge', '', 100);
        $code = $this->code($req, 'code') ?? $this->code($req, 'totp_code');
        $recovery = $this->code($req, 'recovery_code');
        if ($challenge === '') {
            throw ApiException::validation(['challenge' => 'The sign-in challenge is missing. Please sign in again.']);
        }
        if ($code === null && $recovery === null) {
            throw ApiException::validation(['code' => 'Enter the 6-digit code from your authenticator app, or a recovery code.']);
        }
        $result = Auth::completeTwoFactor($req, $challenge, $code, $recovery, $req->bool('remember'));
        return Response::ok($this->payload($result));
    }

    /** POST /auth/logout → 204 (revokes the current session, remember cookie or the API token used). */
    public function logout(Request $req): Response
    {
        Auth::logout($req);
        return Response::noContent();
    }

    /** GET /auth/csrf (auth optional) */
    public function csrf(Request $req): array
    {
        return ['csrf_token' => Csrf::token()];
    }

    /** GET /user — kept for compatibility; UserController::show is the primary handler. */
    public function me(Request $req): array
    {
        return Auth::me($req->user);
    }

    /** POST /auth/password/forgot {email} → always 202 (never reveals whether the address exists). */
    public function forgotPassword(Request $req): Response
    {
        Csrf::assertSameOrigin($req);
        Passwords::requestReset($req->string('email', '', 191), $req);
        return Response::ok([
            'accepted' => true,
            'message'  => 'If an account uses that address, we have sent instructions to reset the password. The link expires in 1 hour.',
        ], [], 202);
    }

    /** POST /auth/password/reset {token, password} */
    public function resetPassword(Request $req): Response
    {
        Csrf::assertSameOrigin($req);
        $token = $req->string('token', '', 200);
        $password = $req->input('password');
        $password = is_string($password) ? $password : '';
        if ($token === '') {
            throw ApiException::validation(['token' => 'Enter the reset code from the e-mail.']);
        }
        if ($password === '') {
            throw ApiException::validation(['password' => 'Choose a new password.']);
        }
        Passwords::completeReset($token, $password, $req);
        return Response::ok(['reset' => true, 'message' => 'Your password has been changed. You can now sign in.']);
    }

    // ------------------------------------------------------------------ helpers

    private function payload(array $result): array
    {
        if ($result['status'] === 'two_factor') {
            return [
                'two_factor_required' => true,
                'challenge'           => $result['challenge'],
                'methods'             => ['totp', 'recovery'],
                'expires_in'          => Auth::CHALLENGE_TTL,
            ];
        }
        if (isset($result['token'])) {
            // API clients get a bearer token and no cookie session, so there is no CSRF token.
            return [
                'user'       => Auth::me($result['user']),
                'csrf_token' => null,
                'token'      => $result['token']['token'],
                'token_info' => array_diff_key($result['token'], ['token' => true]),
            ];
        }
        return ['user' => Auth::me($result['user']), 'csrf_token' => Csrf::token()];
    }

    private function code(Request $req, string $key): ?string
    {
        $v = $req->input($key);
        if (is_int($v)) {
            $v = str_pad((string) $v, 6, '0', STR_PAD_LEFT);
        }
        if (!is_string($v)) {
            return null;
        }
        $v = trim($v);
        return $v === '' ? null : mb_substr($v, 0, 64);
    }
}
