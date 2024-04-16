<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class JWT extends Model
{

    protected $table = 'personal_access_tokens';
    protected $fillable = ['id', 'user_id', 'revoked', 'name'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
