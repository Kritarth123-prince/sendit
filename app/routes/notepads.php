<?php
declare(strict_types=1);

use FT\Controllers\Api\NotepadController;
use FT\Http\Router;

// Owner: Notepads — team and private notepads (the legacy collaborative notepad), autosave with
// optimistic concurrency, history and presence. Not for guests. Autosaves and presence heartbeats
// use their own rate bucket ('notepad') so normal typing never eats into the general 'api' one.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/notepads', [NotepadController::class, 'index']);
        $r->post('/notepads', [NotepadController::class, 'store']);
        $r->get('/notepads/{id:\d+}', [NotepadController::class, 'show']);
        $r->patch('/notepads/{id:\d+}', [NotepadController::class, 'update']);
        $r->delete('/notepads/{id:\d+}', [NotepadController::class, 'destroy']);
        $r->put('/notepads/{id:\d+}/content', [NotepadController::class, 'saveContent'], ['rate' => 'notepad']);
        $r->get('/notepads/{id:\d+}/revisions', [NotepadController::class, 'revisions']);
        $r->get('/notepads/{id:\d+}/revisions/{rid:\d+}', [NotepadController::class, 'revision']);
        $r->post('/notepads/{id:\d+}/revisions/{rid:\d+}/restore', [NotepadController::class, 'restore']);
        $r->post('/notepads/{id:\d+}/presence', [NotepadController::class, 'presence'], ['rate' => 'notepad']);
        $r->delete('/notepads/{id:\d+}/presence', [NotepadController::class, 'leave'], ['rate' => 'notepad']);
    }, ['guest' => false]);
};
