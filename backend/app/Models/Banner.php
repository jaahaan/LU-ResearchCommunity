<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Banner extends Model
{
    protected $fillable = [
        'image',
        'type',
        'order_no',
        'isActive',
        'title',
        'link',
        'btn_text',
    ];
    use HasFactory;
}
