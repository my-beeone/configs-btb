<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use App\Models;

class ChangePasswordCommand extends Command
{

    /**
     * @var string
     */
    protected $signature = 'c:p {phone} {back}';

    /**
     * @var string
     */
    protected $description = "Temporarily change user's password";

    /**
     * @return void
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function handle(): void
    {
        $phone = $this->argument('phone');

        /** @var Models\User $user */
        $user = Models\User::query()
            ->where('phone', $phone)
            ->first()
        ;

        if (is_null($user)) {
            $this->error('Пользователь не найден!');
            exit;
        }

        if ($this->argument('back') == 't') {
            $this->backPassword($user, $phone);
        } else {
            $this->setTestPassword($user, $phone);
        }
    }

    /**
     * @param \App\Models\User $user
     * @param int              $phone
     *
     * @return void
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function backPassword(Models\User $user, int $phone): void
    {
        $file = Storage::disk('local')
            ->get("users/passwords/$phone.json")
        ;

        if (!Hash::check('adminadmin', $user->password)) {
            $this->error('Пароль сброшен пользователем!');
        } else {
            $user->update(
                [
                    'password' => json_decode($file)->password,
                ]
            );
        }

        Storage::disk('local')
            ->delete("users/passwords/$phone.json")
        ;
    }

    /**
     * @param \App\Models\User $user
     * @param int              $phone
     *
     * @return void
     */
    private function setTestPassword(Models\User $user, int $phone): void
    {
        $data = json_encode(
            [
                'password' => $user->password,
                'phone'    => $phone,
            ],
            JSON_PRETTY_PRINT
        );

        if (Hash::check('adminadmin', $user->password)) {
            $this->error('Пароль уже тестовый!');
            exit;
        }

        Storage::disk('local')
            ->put("users/passwords/$phone.json", $data)
        ;

        $user->update(
            [
                'password' => Hash::make('adminadmin'),
            ]
        );
    }
}
