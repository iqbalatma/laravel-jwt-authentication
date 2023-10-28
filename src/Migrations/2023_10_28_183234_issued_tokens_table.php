<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create("issued_tokens", function (Blueprint $table){
            $table->uuid("id")->primary();
            $table->string("subject_id");
            $table->string("jti");
            $table->enum("token_type", TokenType::values());
            $table->string("user_agent");
            $table->timestamp("expired_at");
            $table->timestamps();
            $table->index(["subject_id", "jti", "token_type", "user_agent"]);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists("issued_tokens");
    }
};
