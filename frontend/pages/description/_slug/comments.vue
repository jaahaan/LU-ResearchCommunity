<template>
  <div class="comment">
    <h4 class="menu-item--title">Comments</h4>
    <div v-if="isLoading" class="loader">
      <h1 />
    </div>
    <div v-else>
      <div class="comment-box">
        <img :src="authUser.image" alt="img" />
        <textarea
          v-model="data.comment"
          class="form-control form-outline"
          placeholder="Add a comment"
          ref="textarea"
          rows="1"
          @focus="resizeTextarea"
          @keyup="resizeTextarea"
          @click="showButton"
        ></textarea>
        <Icon type="md-send" v-if="showbtn == true" @click="addComment" />
      </div>
      <div
        v-if="comments.length > 0"
        v-for="(comment, index) in comments"
        :key="index"
      >
        <div
          class="comment-section"
          v-bind:class="{ commentActive: commentId == comment.id }"
        >
          <img :src="comment.image" alt="img" />
          <div class="comment-section-content">
            <div class="comment-section-content-main">
              <nuxt-link :to="`/profile/${comment.user_slug}/overview`">
                {{ comment.name }}
              </nuxt-link>
              <!-- . {{ comment.created_at }} -->

              <p>
                {{ comment.comment }}
              </p>
            </div>
            <div class="comment-section-content-like">
              <div>
                <span>
                  <a
                    v-on:click="CommentLike(index)"
                    v-bind:class="{
                      active: comment.authUserCommentLike == 'yes',
                    }"
                  >
                    Like
                  </a>
                </span>
                <a v-on:click="showReplyBox(index)">Reply</a>
              </div>
              <div
                v-if="comment.comment_like_count"
                @click="getCommentLikedUser(index)"
              >
                {{ comment.comment_like_count }}
                <i class="fa-solid fa-thumbs-up"></i>
              </div>
            </div>
          </div>
        </div>
        <div
          class="reply"
          v-if="comment.comment_reply_count > 0 && comment_id !== comment.id"
        >
          <span class="reply-item"
            ><i
              data-visualcompletion="css-img"
              class="x1b0d499 x1d69dk1"
              style="
                background-image: url('https://static.xx.fbcdn.net/rsrc.php/v3/y6/r/LuI9mMlkMfm.png?_nc_eui2=AeHodVwwG5T1njR17oQGXXcMMyVdDR0OFnwzJV0NHQ4WfDrFp5XeVake6Gk9eA4jRqS77wkkIlDeyGr5Id_cI0_d');
                background-position: 0px -672px;
                background-size: auto;
                width: 16px;
                height: 16px;
                background-repeat: no-repeat;
                display: inline-block;
              "
            ></i></span
          ><span class="reply-item"
            ><a
              class="reply-item-count"
              v-on:click="showCommentReplies(comment.id)"
              v-if="comment.comment_reply_count > 1"
              >{{ comment.comment_reply_count }} Replies</a
            ><a
              class="reply-item-count"
              v-on:click="showCommentReplies(comment.id)"
              v-else
              >{{ comment.comment_reply_count }} Reply</a
            ></span
          >
        </div>

        <div class="comment-reply">
          <div
            class="comment-reply-box"
            v-if="showreplybox == true && commentindex == index"
          >
            <img :src="authUser.image" alt="img" />
            <textarea
              v-model="data.commentReply"
              class="form-outline"
              placeholder="Add a comment"
              :ref="`commentReply${data.commentReply}`"
              rows="1"
              @focus="resizeTextarea"
              @keyup="resizeTextarea"
            ></textarea>
            <Icon type="md-send" @click="addCommentReply(comment)" />
          </div>
          <div
            v-if="isReplyLoading && comment_id == comment.id"
            class="loader-sm"
          >
            <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
          </div>
          <div
            class="comment-reply-section"
            v-for="(reply, index) in commentReplies"
            :key="index"
            v-if="comment.id == reply.comment_id && showcommentreplies == true"
          >
            <img :src="reply.image" alt="img" />
            <div class="comment-reply-section-content">
              <div class="comment-reply-section-content-main">
                <nuxt-link :to="`/profile/${reply.user_slug}/overview`">
                  {{ reply.name }}
                </nuxt-link>
                <!-- . {{ comment.created_at }} -->

                <p>
                  {{ reply.comment }}
                </p>
              </div>
              <div class="comment-reply-section-content-like">
                <div>
                  <a
                    v-on:click="CommentReplyLike(index)"
                    v-bind:class="{
                      active: reply.authUserReplyCommentLike == 'yes',
                    }"
                  >
                    Like
                  </a>
                </div>
                <div
                  v-if="reply.comment_reply_like_count"
                  @click="getCommentReplyLikedUser(index)"
                >
                  {{ reply.comment_reply_like_count }}
                  <i class="fa-solid fa-thumbs-up"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <Modal
        v-model="commentLikedUserModal"
        title="People Who Liked"
        :mask-closable="true"
        :closable="true"
      >
        <div class="comment-liked" v-for="user in commentLikedUser">
          <img :src="user.image" alt="img" />
          <nuxt-link :to="`/profile/${user.user_slug}/overview`">
            {{ user.name }}
          </nuxt-link>
        </div>
        <div slot="footer"></div>
      </Modal>
    </div>
  </div>
</template>
<script>
const { io } = require("socket.io-client");
import { mapGetters } from "vuex";

export default {
  components: {},
  middleware: "auth",
  data() {
    return {
      isReplyLoading: false,
      socket: null,
      details: [],
      // comments: [],
      commentReplies: [],
      commentLikedUser: [],
      commentReplyLikedUser: [],
      commentindex: -1,
      comment_id: -1,
      post_slug: "",
      post_id: "",
      isPostInfoIndex: 1,
      isLoading: true,
      upVoteCount: 0,
      downVoteCount: 0,
      avgVoteCount: 0,
      authUserVoteCount: "",
      showbtn: false,
      showreplybox: false,
      showcommentreplies: false,
      data: {
        comment: "",
        commentReply: "",
      },
      comment_like_count: 0,
      authUserCommentLike: "",
      comment_reply_like_count: 0,
      authUserReplyCommentLike: "",
      commentLikedUserModal: false,
      hooperTrendingOffer: {
        commentsToShow: 1,
        centerMode: false,
        breakpoints: {
          768: {
            centerMode: false,
            itemsToShow: 2,
          },
        },
      },
    };
  },
  computed: {
    ...mapGetters({
      commentId: "commentId",
      comments: "getAllComments",
    }),
  },
  methods: {
    async addComment() {
      this.showreplybox = false;
      if (this.data.comment.trim() == "")
        return this.e("Comment field is empty!!!");
      let obj = {
        id: this.details.id,
        comment: this.data.comment,
      };

      // var today = new Date();
      // var date =
      //     today.getFullYear() +
      //     "-" +
      //     (today.getMonth() + 1) +
      //     "-" +
      //     today.getDate();
      // var time =
      //     today.getHours() +
      //     ":" +
      //     today.getMinutes() +
      //     ":" +
      //     today.getSeconds();
      let notificationObj = {
        id: this.details.user_id,
      };

      // if (res.status == 201) {
      const res = await this.callApi("post", "/api/add_comment", obj);
      if (res.status == 201) {
        let d = {
          id: res.data.data.id,
          post_id: this.details.id,
          user_id: this.authUser.id,
          comment: this.data.comment,
          image: this.authUser.image,
          name: this.authUser.name,
          user_slug: this.authUser.slug,
          // created_at: date + " " + time,
          comment_like_count: 0,
        };
        this.$store.commit("pushAllComments", d);
        // this.comments.unshift(data);
        this.data.comment = "";
        this.socket.emit("notification", notificationObj);
      } else {
        this.swr();
      }
    },
    async getComment() {
      const res = await this.callApi(
        "get",
        `/api/get_comments/${this.post_slug}`
      );

      if (res.status == 200) {
        this.$store.commit("setAllComments", res.data.data);
        // this.comments = res1.data.data;
      }
    },
    async CommentLike(index) {
      if (this.comments[index].user_id != this.authUser.id) {
        let obj = {
          id: this.comments[index].id,
        };
        let notificationObj = {
          id: this.comments[index].user_id,
        };
        const res = await this.callApi("post", "/api/comment_like", obj);
        if (res.status == 201) {
          this.comments[index].comment_like_count += 1;
          this.comments[index].authUserCommentLike = "yes";
          this.socket.emit("notification", notificationObj);
        } else {
          this.comments[index].comment_like_count -= 1;
          this.comments[index].authUserCommentLike = "no";
        }
      } else {
        this.i("You can't like your own comment");
      }
    },
    async getCommentLikedUser(index) {
      let obj = {
        id: this.comments[index].id,
      };
      console.log(this.comments[index].id);
      const res = await this.callApi(
        "get",
        `/api/get_comment_liked_user?id=${this.comments[index].id}`
      );
      if (res.status == 200) {
        this.commentLikedUser = res.data.data;
        this.commentLikedUserModal = true;
      } else {
        this.swr();
      }
    },
    resizeTextarea(e) {
      let area = e.target;
      area.style.height = "auto";
      area.style.overflow = "hidden";
      area.style.height = area.scrollHeight + "px";
      // this.showbtn = true;
    },
    showButton() {
      this.showbtn = true;
    },
    showReplyBox(index) {
      this.showreplybox = true;
      this.commentindex = index;
      this.$nextTick(() => {
        if (this.$refs["commentReply" + this.data.commentReply]) {
          this.$refs["commentReply" + this.data.commentReply][0].focus();
        }
      });
    },
    async addCommentReply(comment) {
      if (this.data.commentReply.trim() == "")
        return this.e("Field is empty!!!");
      let obj = {
        post_id: this.details.id,
        comment_id: comment.id,
        commentReply: this.data.commentReply,
      };
      let notificationObj = {
        id: comment.user_id,
      };
      const res = await this.callApi("post", "/api/add_comment_reply", obj);
      if (res.status == 201) {
        let data = {
          id: res.data.id,
          user_id: this.authUser.id,
          post_id: this.details.id,
          comment_id: comment.id,
          comment: this.data.commentReply,
          image: this.authUser.image,
          name: this.authUser.name,
          comment_reply_like_count: 0,
        };
        this.commentReplies.unshift(data);
        this.showCommentReplies1(comment.id);
        this.data.commentReply = "";
        this.socket.emit("notification", notificationObj);
      } else {
        this.swr();
      }
    },
    async showCommentReplies1(id) {
      this.showcommentreplies = true;
      this.comment_id = id;
      const res = await this.callApi(
        "get",
        `/api/get_comment_replies?comment_id=${id}`
      );
      if (res.status == 200) {
        this.commentReplies = res.data.data;
      }
    },

    async showCommentReplies(id) {
      this.showcommentreplies = true;
      this.comment_id = id;
      this.isReplyLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_comment_replies?comment_id=${id}`
      );
      if (res.status == 200) {
        this.commentReplies = res.data.data;
      }
      this.isReplyLoading = false;
    },

    async CommentReplyLike(index) {
      if (this.commentReplies[index].user_id != this.authUser.id) {
        let obj = {
          id: this.commentReplies[index].id,
        };
        let notificationObj = {
          id: this.commentReplies[index].user_id,
        };
        const res = await this.callApi("post", "/api/comment_reply_like", obj);
        if (res.status == 201) {
          this.commentReplies[index].comment_reply_like_count += 1;
          this.commentReplies[index].authUserReplyCommentLike = "yes";
          this.socket.emit("notification", notificationObj);
        } else {
          this.commentReplies[index].comment_reply_like_count -= 1;
          this.commentReplies[index].authUserReplyCommentLike = "no";
        }
      } else {
        this.i("You can't like your own reply");
      }
    },
    async getCommentReplyLikedUser(index) {
      let obj = {
        id: this.commentReplies[index].id,
      };
      const res = await this.callApi(
        "get",
        `/api/get_comment_reply_liked_user?id=${this.commentReplies[index].id}`
      );
      if (res.status == 200) {
        this.commentLikedUser = res.data.data;
        this.commentLikedUserModal = true;
      } else {
        this.swr();
      }
    },

    hideButton() {
      this.showbtn = false;
    },
  },
  mounted() {
    // document.addEventListener("click", this.hideSearchbar);
    this.socket = io("http://localhost:5000", {
      methods: ["GET", "POST"],
      transports: ["websocket"],
      credentials: true,
    });
  },
  async created() {
    // this.token = window.Laravel.csrfToken;
    this.post_slug = this.$route.params.slug;
    console.log(this.post_slug);
    console.log("id" + this.commentId);

    const res = await this.callApi(
      "get",
      `/api/post_details/${this.post_slug}`
    );
    if (this.authUser) {
      // const resR = await this.callApi("get", `/api/get_comment_replies`);
      // if (resR.status == 200) {
      //   this.commentReplies = resR.data.data;
      // }
      const res1 = await this.callApi(
        "get",
        `/api/get_comments/${this.post_slug}`
      );

      if (res1.status == 200) {
        this.$store.commit("setAllComments", res1.data.data);
        // this.comments = res1.data.data;
      }
    }
    if (res.status == 200) {
      this.details = res.data.data[0];
      this.upVoteCount = this.details.upVote;
      this.downVoteCount = this.details.downVote;
      this.avgVoteCount = this.details.avgVote;
      this.authUserVoteCount = this.details.authUserVote;
      this.post_id = this.details.id;
      if (this.authUser) {
        const res1 = await this.callApi("post", `/api/read/${this.details.id}`);
      }
    } else {
      this.swr();
    }

    this.isLoading = false;
  },
};
</script>
