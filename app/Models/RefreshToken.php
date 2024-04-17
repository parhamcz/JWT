<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class RefreshToken extends Model
{
    protected $table = 'refresh_tokens';
    protected $fillable = ['uuid', 'user_id', 'name', 'revoked'];
    protected $primaryKey = 'uuid';

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
