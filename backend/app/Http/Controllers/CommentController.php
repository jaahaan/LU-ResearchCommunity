<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Auth;
use App\Models\User;
use App\Models\Post;
use App\Models\CommentLike;
use App\Models\Comment;
use App\Models\CommentReply;
use App\Models\CommentReplyLike;
use App\Notifications\CommentNotification;
use App\Models\Notification;
use App\Models\Notify;

date_default_timezone_set('Asia/Dhaka');

class CommentController extends Controller
{
    //comments
    public function getComments($slug){
        $query = Post::where('slug',$slug)->first();

        $data = Comment::where('post_id',$query->id)->with('user', 'like', 'replyCount')->orderBy('id', 'desc')->get();
        
        $formattedData = [];

        foreach($data as $value){
            $comment = $value;
            $likecheck = CommentLike::where(['comment_id'=>$comment->id])->first();
            $AuthLikeCheck = CommentLike::where(['user_id'=>Auth::user()->id,'comment_id'=>$comment->id])->first();
            $replycheck = CommentReply::where(['comment_id'=>$comment->id])->first();

            if($likecheck){
                $comment['comment_like_count'] =$comment->like->comment_like_count;
            } if(!$likecheck){
                $comment['comment_like_count'] = 0;
            } if($AuthLikeCheck){
                $comment['authUserCommentLike'] = 'yes';
            } if(!$AuthLikeCheck){
                $comment['authUserCommentLike'] = 'no';
            } 

            if($replycheck){
                $comment['comment_reply_count'] = $comment->replyCount->comment_reply_count;
            } if(!$replycheck){
                $comment['comment_reply_count'] = 0;
            }

            $comment['image'] = $comment->user->image;
            $comment['name'] = $comment->user->name;
            $comment['user_slug'] = $comment->user->slug;
            $comment['department'] = $comment->user->department;
            $comment['designation'] = $comment->user->designation;
            unset($comment['user']);
            unset($comment['like']);
            unset($comment['replyCount']);

            array_push($formattedData, $comment);
        }
        return response()->json([
            'success'=> true,
            'data'=>$formattedData,
        ],200);
    }

    public function commentLike(Request $request){
        $checkLike = CommentLike::where(['user_id'=>Auth::user()->id,'comment_id'=>$request->id])->first();

        \Log::info('$check');
        \Log::info($checkLike);
        $comment = Comment::where('id',$request->id)->first();
        // $post = Post::where('id',$comment->post_id)->first();
    	if ($checkLike) {
    		CommentLike::where(['user_id'=>Auth::user()->id,'comment_id'=>$request->id])->delete();
            Notify::where(['post_id'=>$comment->post_id,'user_id'=>Auth::user()->id, 'comment_id' => $request->id, 'msg'=>'liked your comment'])->delete();
    		return 'deleted';
    	} else{
            // $authUser = Auth::user();
            // $commentUser = User::where('id', $comment->user_id)->first();
            $msg = "liked your comment";
            // $commentUser->notify(new CommentNotification($authUser, $post, $comment_id, $msg));
            Notify::create([
                'type' => 'commentLike',
                'notifiable_id' => $comment->user_id,
                'user_id' => Auth::user()->id,
	    	    'post_id' => $comment->post_id,
	    	    'comment_id' => $request->id,
                'msg'=> $msg,
            ]);
            return CommentLike::create([
                'user_id' => Auth::user()->id,
	    	    'comment_id' => $request->id,
            ]);
        }
        
    }

    public function getCommentLikedUser(Request $request){
        \Log::info($request);
        $data = CommentLike::where('comment_id',$request->id)->with('user')->get();
        
        $formattedData = [];

        foreach($data as $value){
            $LikedUser = $value;

            $LikedUser['image'] = $LikedUser->user->image;
            $LikedUser['name'] = $LikedUser->user->name;
            $LikedUser['user_slug'] = $LikedUser->user->slug;
            unset($LikedUser['user']);
            array_push($formattedData, $LikedUser);
        }
        return response()->json([
            'success'=> true,
            'data'=>$formattedData,
        ],200);
        
    }

    public function addComment(Request $request){
        $comment =  Comment::create([
            'user_id' => Auth::user()->id,
            'post_id' => $request->id,
            'comment' => $request->comment,
        ]);
        $post = Post::where('id',$request->id)->first();
        // $comment_id = $comment->id;
        // $authUser = Auth::user();
        // $postUser = User::where('id', $post->user_id)->first();
        $msg = "commented your";
        if(Auth::user()->id != $post->user_id){
            // $postUser->notify(new CommentNotification($authUser, $post, $comment_id, $msg));
            Notify::create([
                'type' => 'comment',
                'notifiable_id' => $post->user_id,
                'user_id' => Auth::user()->id,
	    	    'post_id' => $comment->post_id,
	    	    'comment_id' => $comment->id,
                'msg'=> $msg,
            ]);
        }
        return response()->json([
            'success'=> true,
            'data'=>$comment,
        ],201);
    }

    //Comment Reply
    public function addCommentReply(Request $request){
        $post = Post::where('id',$request->post_id)->first();
        $comment = Comment::where('id',$request->comment_id)->first();
        // $comment_id = $comment->id;
        // $authUser = Auth::user();
        $commentUser = User::where('id', $comment->user_id)->first();
        $comment_reply = CommentReply::where('comment_id' , $request->comment_id)->where('user_id' , '!=', Auth::user()->id)->get();
        if($comment->user_id == Auth::user()->id && $comment_reply){
            foreach ($comment_reply as $a) {
                // $commentReplyUser = User::where('id', $a->user_id)->first();
                $msg = "replied a comment you are following";
                // $commentReplyUser->notify(new CommentNotification($authUser, $post, $comment_id, $msg));
                Notify::create([
                    'type' => 'commentReply',
                    'notifiable_id' => $a->user_id,
                    'user_id' => Auth::user()->id,
                    'post_id' => $request->post_id,
                    'comment_id' => $request->comment_id,
                    'msg'=> $msg,
                ]);
            }
        } else{
            $msg = "replied your comment";
            // $commentUser->notify(new CommentNotification($authUser, $post, $comment_id, $msg));
            Notify::create([
                'type' => 'commentReply',
                'notifiable_id' => $comment->user_id,
                'user_id' => Auth::user()->id,
                'post_id' => $request->post_id,
                'comment_id' => $request->comment_id,
                'msg'=> $msg,
            ]);
        }
        return CommentReply::create([
            'user_id' => Auth::user()->id,
            'post_id' => $request->post_id,
            'comment_id' => $request->comment_id,
            'comment' => $request->commentReply,
        ], 201);
    }

    public function getCommentReplies(Request $request){

        $data = CommentReply::where('comment_id',$request->comment_id)->with('user')->orderBy('id', 'desc')->get();
        
        $formattedData = [];

        foreach($data as $value){
            $comment = $value;
            $likecheck = CommentReplyLike::where(['comment_reply_id'=>$comment->id])->first();
            $AuthLikeCheck = CommentReplyLike::where(['user_id'=>Auth::user()->id,'comment_reply_id'=>$comment->id])->first();
            // $replycheck = CommentReply::where(['comment_id'=>$comment->id])->first();

            if($likecheck){
                $comment['comment_reply_like_count'] =$comment->like->comment_reply_like_count;
            } if(!$likecheck){
                $comment['comment_reply_like_count'] = 0;
            } if($AuthLikeCheck){
                $comment['authUserReplyCommentLike'] = 'yes';
            } if(!$AuthLikeCheck){
                $comment['authUserReplyCommentLike'] = 'no';
            } 

            // if($replycheck){
            //     $comment['comment_reply_count'] = $comment->replyCount->comment_reply_count;
            // } if(!$replycheck){
            //     $comment['comment_reply_count'] = 0;
            // }

            $comment['image'] = $comment->user->image;
            $comment['name'] = $comment->user->name;
            $comment['user_slug'] = $comment->user->slug;
            $comment['department'] = $comment->user->department;
            $comment['designation'] = $comment->user->designation;
            unset($comment['user']);
            unset($comment['like']);
            unset($comment['replyCount']);

            array_push($formattedData, $comment);
        }
        return response()->json([
            'success'=> true,
            'data'=>$formattedData,
        ],200);
    }

    public function commentReplyLike(Request $request){
        $checkLike = CommentReplyLike::where(['user_id'=>Auth::user()->id,'comment_reply_id'=>$request->id])->first();

        \Log::info('$check');
        \Log::info($checkLike);
        $comment_reply = CommentReply::where('id',$request->id)->first();
        // $post = Post::where('id',$comment_reply->post_id)->first();
        // $comment_id = $comment_reply->comment_id;
        // $authUser = Auth::user();
        $msg = "liked your reply";
    	if ($checkLike) {
    		CommentReplyLike::where(['user_id'=>Auth::user()->id,'comment_reply_id'=>$request->id])->delete();
            Notify::where(['post_id'=>$comment_reply->post_id,'user_id'=>Auth::user()->id, 'comment_id' => $comment_reply->comment_id, 'msg'=> $msg])->delete();
    		return 'deleted';
    	} else{
            
            // $commentUser = User::where('id', $comment_reply->user_id)->first();
            // $commentUser->notify(new CommentNotification($authUser, $post, $comment_id, $msg));
            Notify::create([
                'type' => 'commentReplyLike',
                'notifiable_id' => $comment_reply->user_id,
                'user_id' => Auth::user()->id,
                'post_id' => $comment_reply->post_id,
                'comment_id' => $comment_reply->comment_id,
                'msg'=> $msg,
            ]);
            return CommentReplyLike::create([
                'user_id' => Auth::user()->id,
	    	    'comment_reply_id' => $request->id,
            ]);
        }
        
    }

    public function getCommentReplyLikedUser(Request $request){
        \Log::info($request);
        $data = CommentReplyLike::where('comment_reply_id',$request->id)->with('user')->get();
        
        $formattedData = [];

        foreach($data as $value){
            $LikedUser = $value;
            $LikedUser['image'] = $LikedUser->user->image;
            $LikedUser['name'] = $LikedUser->user->name;
            $LikedUser['user_slug'] = $LikedUser->user->slug;
            unset($LikedUser['user']);
            array_push($formattedData, $LikedUser);
        }
        return response()->json([
            'success'=> true,
            'data'=>$formattedData,
        ],200);
        
    }
}
