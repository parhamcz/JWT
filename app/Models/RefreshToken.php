<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class RefreshToken extends Model
{
    protected $table = 'refresh_tokens';
    protected $fillable = ['user_id', 'name', 'revoked'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
