<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class JWT extends Model
{

    protected $table = 'personal_access_tokens';
    protected $fillable = ['uuid', 'user_id', 'revoked', 'name'];

    protected $primaryKey = 'uuid';

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
