<?php

namespace Iqbalatma\LaravelJwtAuthentication\Models;

use App\Enums\TokenType;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\SubjectIdNullException;


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

    /**
     * @param int|string|null $subjectId
     * @return Collection
     * @throws SubjectIdNullException
     */
    public static function getAllTokenBySubject(int|string|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            if (!Auth::id()) {
                throw new SubjectIdNullException();
            }
            $subjectId = Auth::id();
        }
        return (new static())->where("subject_id", $subjectId)->get();
    }

    /**
     * @param int|string|null $subjectId
     * @return Collection
     * @throws SubjectIdNullException
     */
    public static function getAllTokenRefreshBySubject(int|string|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            if (!Auth::id()) {
                throw new SubjectIdNullException();
            }
            $subjectId = Auth::id();
        }
        return (new static())->where("subject_id", $subjectId)->where("token_type", TokenType::REFRESH->value)->get();
    }


    /**
     * @param int|string|null $subjectId
     * @return Collection
     * @throws SubjectIdNullException
     */
    public static function getAllTokenAccessBySubject(int|string|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            if (!Auth::id()) {
                throw new SubjectIdNullException();
            }
            $subjectId = Auth::id();
        }
        return (new static())->where("subject_id", $subjectId)->where("token_type", TokenType::ACCESS->value)->get();
    }

    /**
     * @param string $userAgent
     * @param int|string|null $subjectId
     * @return Collection
     * @throws SubjectIdNullException
     */
    public static function getAllTokenAccessByUserAgentAndSubject(string $userAgent, int|string|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            if (!Auth::id()) {
                throw new SubjectIdNullException();
            }
            $subjectId = Auth::id();
        }
        return (new static())->where("subject_id", $subjectId)
            ->where("user_agent", $userAgent)
            ->where("token_type", TokenType::ACCESS->value)
            ->get();
    }

    /**
     * @param string $userAgent
     * @param int|string|null $subjectId
     * @return Collection
     * @throws SubjectIdNullException
     */
    public static function getAllTokenRefreshByUserAgentAndSubject(string $userAgent, int|string|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            if (!Auth::id()) {
                throw new SubjectIdNullException();
            }
            $subjectId = Auth::id();
        }
        return (new static())->where("subject_id", $subjectId)
            ->where("user_agent", $userAgent)
            ->where("token_type", TokenType::REFRESH->value)
            ->get();
    }


    /**
     * @param string $userAgent
     * @param int|string|null $subjectId
     * @return Collection
     * @throws SubjectIdNullException
     */
    public static function getAllTokenByUserAgentAndSubject(string $userAgent, int|string|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            if (!Auth::id()) {
                throw new SubjectIdNullException();
            }
            $subjectId = Auth::id();
        }
        return (new static())->where("subject_id", $subjectId)
            ->where("user_agent", $userAgent)
            ->get();
    }


    /**
     * @param string|int|null $subjectId
     * @return Collection
     * @throws SubjectIdNullException
     */
    public static function getAllTokenAccessBySubjectGroupByUserAgent(string|int|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            if (!Auth::id()) {
                throw new SubjectIdNullException();
            }
            $subjectId = Auth::id();
        }
        return (new static())->select('*')
            ->joinSub(
                self::select('subject_id', 'token_type', 'user_agent', DB::raw('MAX(created_at) as latest'))
                    ->where('subject_id', $subjectId)
                    ->where('token_type', TokenType::ACCESS->value)
                    ->groupBy('token_type', 'subject_id', 'user_agent'),
                'subquery',
                function ($join) {
                    $join->on('issued_tokens.subject_id', '=', 'subquery.subject_id');
                    $join->on('issued_tokens.user_agent', '=', 'subquery.user_agent');
                    $join->on('issued_tokens.token_type', '=', 'subquery.token_type');
                    $join->on('issued_tokens.created_at', '=', 'subquery.latest');
                }
            )->get();
    }
}
