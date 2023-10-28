<?php

namespace Iqbalatma\LaravelJwtAuthentication\Models;

use App\Enums\TokenType;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;


/**
 * @property string id
 * @property string subject_id
 * @property string jti
 * @property TokenType token_type
 * @property string user_agent
 * @property Carbon expired_at
 * @property Carbon created_at
 * @property Carbon updated_at
 */
class IssuedToken extends Model
{
    use HasFactory, HasUuids;

    protected $fillable = [
        "subject_id", "jti", "token_type", "user_agent", "expired_at"
    ];


    /**
     * @param string $jti
     * @return IssuedToken|null
     */
    public static function getTokenByJTI(string $jti): IssuedToken|null
    {
        return (new static())->where("jti", $jti)->first();
    }

    /**
     * @param string $subjectId
     * @return IssuedToken|null
     */
    public static function getTokenBySubjectId(string $subjectId): IssuedToken|null
    {
        return (new static())->where("subject_id", $subjectId)->first();
    }



}
