<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Ramsey\Uuid\Uuid;

class JWT extends Model
{

    protected $table = 'personal_access_tokens';
    protected $fillable = ['uuid', 'user_id', 'revoked', 'name'];

    protected $primaryKey = 'uuid';
    protected $casts = [
        'uuid' => 'string'
    ];
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
