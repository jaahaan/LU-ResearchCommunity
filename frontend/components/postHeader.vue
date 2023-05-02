<template>
  <div>
    <div v-if="isLoading" class="loader-lg">
      <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
    </div>
    <div v-else class="container pt-4 pb-4">
      <section class="post-section">
        <div class="post-menu">
          <div class="post-menu--header">
            <div class="post-menu--header--image">
              <img :src="`${http + details.image}`" alt="" />
            </div>
            <div class="content">
              <nuxt-link :to="`/profile/${details.user_slug}/overview`">
                {{ details.name }}
              </nuxt-link>
              <p>
                {{ details.designation }}
                .
                {{ details.department.department_name }}
              </p>
            </div>
          </div>
          <ul class="post-menu--list">
            <li class="post-menu--list---item">
              <nuxt-link
                class="menu-link"
                aria-current="page"
                :to="`/description/${details.slug}/overview`"
                ><i class="las la-icons"></i>
                <h4>Overview</h4></nuxt-link
              >
            </li>
            <li class="post-menu--list---item" v-if="authUser">
              <nuxt-link
                class="menu-link"
                aria-current="page"
                :to="`/description/${details.slug}/comments`"
                ><i class="fa-solid fa-comment"></i>
                <h4>Comments</h4></nuxt-link
              >
            </li>
          </ul>
        </div>

        <!-- post description -->
        <div class="post-description menu-item">
          <div class="menu-item-box">
            <div class="post-details">
              <h4 class="menu-item--title">
                {{ details.title }}
              </h4>
              <button class="main-btn main-btn__bg">
                {{ details.type }}
              </button>
              <h5 class="sub-title" v-if="details.type == 'Conference Paper'">
                Conference: 2021 International Conference on Science &
                Contemporary Technologies (ICSCT)
              </h5>
              <div class="sub-title mt-2" v-if="details.affiliation">
                <p>
                  <i class="fa-solid fa-graduation-cap"></i> Associated with
                  {{ details.affiliation }}
                </p>
              </div>
              <hooper
                :settings="hooperImage"
                :wheelControl="false"
                v-if="details.images.length > 0"
              >
                <slide
                  class="post-image"
                  v-for="(image, index) in details.images"
                  :key="index"
                >
                  <img :src="`${http + image.image_name}`" />
                  <div class="post-image-cover">
                    <i
                      class="lni lni-search-alt"
                      @click="handleView(image.image_name, index)"
                    ></i>
                  </div>
                </slide>

                <hooper-navigation
                  slot="hooper-addons"
                  class="hooper-relatedResearch_button"
                ></hooper-navigation>
              </hooper>

              <div v-if="details.authors.length">
                <div v-if="details.authors.length > 1">
                  <p v-if="details.type == 'Project'" class="sub-title mt-2">
                    Team Members:
                    <span v-for="(author, index) in details.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }} </nuxt-link
                      ><span
                        class="dot"
                        v-if="details.authors.length - 1 > index"
                        >•</span
                      >
                    </span>
                  </p>
                  <p v-else class="sub-title mt-2">
                    Authors:
                    <span v-for="(author, index) in details.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }} </nuxt-link
                      ><span
                        class="dot"
                        v-if="details.authors.length - 1 > index"
                        >•</span
                      >
                    </span>
                  </p>
                </div>
                <div v-else>
                  <p class="sub-title mt-2" v-if="details.type == 'Project'">
                    Team Member:
                    <span v-for="(author, index) in details.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}</nuxt-link
                      ><span
                        class="dot"
                        v-if="details.authors.length - 1 > index"
                        >•</span
                      ></span
                    >
                  </p>
                  <p class="sub-title mt-2" v-else>
                    Author:
                    <span v-for="(author, index) in details.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}
                      </nuxt-link>
                      <span
                        class="dot"
                        v-if="details.authors.length - 1 > index"
                        >•</span
                      >
                    </span>
                  </p>
                </div>
              </div>
              <h6>
                <!-- {{ details.created_at }} . -->
                <a v-if="details.read_count > 1"
                  >{{ details.read_count }} Reads</a
                ><a v-else-if="details.read_count <= 1"
                  >{{ details.read_count }} Read</a
                ><span class="dot">•</span><a>{{ upVoteCount }} UpVote</a
                ><span class="dot">•</span><a>{{ downVoteCount }} DownVote</a>
              </h6>

              <div class="footer">
                <p>
                  <a
                    v-if="details.attachment && authUser"
                    class="main-btn main-btn__bg px-lg-4"
                    :href="`https://cameraworldapi.dreamsgallerybd.com/api/download_attachment/${details.attachment}`"
                    >Download <i class="fa-solid fa-download"
                  /></a>
                  <a
                    class="main-btn main-btn__bg px-lg-5"
                    :href="`${details.url}`"
                    v-if="details.url"
                    target="_blank"
                  >
                    Link
                    <i class="fa-solid fa-arrow-up-right-from-square"></i>
                  </a>
                </p>
                <p v-if="authUser">
                  <a v-if="details.like_count" @click="getLikedUser">
                    {{ details.like_count }}
                  </a>

                  <a
                    v-on:click="like"
                    v-bind:class="{
                      active: details.authUserLike == 'yes',
                    }"
                  >
                    <i class="fa-solid fa-thumbs-up"></i>
                  </a>
                </p>
              </div>
            </div>
            <div class="vote" v-if="authUser">
              <span @click="upVote">
                <i
                  :class="[
                    authUserVoteCount == 'up'
                      ? 'las la-caret-up upActive'
                      : 'las la-caret-up',
                    'las la-caret-up',
                  ]"
                ></i>
              </span>
              <h6>{{ avgVoteCount }}</h6>
              <span @click="downVote">
                <i
                  :class="[
                    authUserVoteCount == 'down'
                      ? 'las la-caret-down downActive'
                      : 'las la-caret-down',
                    'las la-caret-down',
                  ]"
                ></i>
              </span>
            </div>
          </div>

          <div class="menu-item-box">
            <Nuxt />
          </div>
        </div>
      </section>
      <!--***************Related Research Section****************-->

      <section
        class="related-research__section"
        v-if="relatedResearch.length > 0"
      >
        <div class="container">
          <div class="dept-header">
            <h2>Related {{ this.details.type }}</h2>
          </div>

          <hooper :settings="hooperTrendingOffer" :wheelControl="false">
            <slide v-for="(research, index) in relatedResearch" :key="index">
              <div class="related_research--section">
                <h4>
                  <nuxt-link :to="`/description/${research.slug}/overview`">
                    {{ research.title }}
                  </nuxt-link>
                </h4>

                <p>{{ research.type }}</p>
                <p>
                  <i class="fa-solid fa-graduation-cap"></i> Associated with
                  {{ research.affiliation }}
                </p>
                <div v-if="research.authors.length">
                  <p
                    v-if="
                      research.authors.length > 1 && research.type != 'Project'
                    "
                    class="mt-2"
                  >
                    Authors:
                    <span v-for="author in research.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}</nuxt-link
                      >
                    </span>
                  </p>
                  <p
                    v-else-if="
                      research.authors.length > 1 && research.type == 'Project'
                    "
                    class="mt-2"
                  >
                    Team Members:
                    <span v-for="author in research.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}</nuxt-link
                      >
                    </span>
                  </p>
                  <p
                    class="mt-2"
                    v-else-if="
                      research.authors.length == 1 && research.type == 'Project'
                    "
                  >
                    Team Member:
                    <span v-for="author in research.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}</nuxt-link
                      >
                    </span>
                  </p>
                  <p
                    class="mt-2"
                    v-else-if="
                      research.authors.length == 1 && research.type != 'Project'
                    "
                  >
                    Author:
                    <span v-for="author in research.authors">
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}</nuxt-link
                      >
                    </span>
                  </p>
                </div>
                <div
                  v-else-if="
                    research.authors.length && research.type == 'Project'
                  "
                >
                  <p v-if="research.authors.length > 1" class="mt-2">
                    Team Members:
                    <span
                      v-for="author in research.authors"
                      v-if="research.authors.length"
                    >
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}</nuxt-link
                      >
                    </span>
                  </p>
                  <p class="mt-2" v-else>
                    Team Member:
                    <span
                      v-for="author in research.authors"
                      v-if="research.authors.length"
                    >
                      <nuxt-link
                        :to="`/profile/${author.slug}/overview`"
                        class="authors"
                        >{{ author.name }}</nuxt-link
                      >
                    </span>
                  </p>
                </div>
              </div>
            </slide>

            <hooper-navigation
              slot="hooper-addons"
              class="hooper-relatedResearch_button"
            ></hooper-navigation>
          </hooper>
        </div>
      </section>

      <Modal
        v-model="likedUserModal"
        title="People Who Liked"
        :mask-closable="true"
        :closable="true"
      >
        <div class="comment-liked" v-for="user in likedUser">
          <img :src="`${http + user.image}`" alt="img" />
          <nuxt-link :to="`/profile/${user.user_slug}/overview`">
            {{ user.name }}
          </nuxt-link>
        </div>
        <div slot="footer"></div>
      </Modal>
      <Modal v-model="visible">
        <img :src="imgName" v-if="visible" style="width: 100%" />
        <div slot="footer"></div>
      </Modal>
    </div>

    <!--***** Comment Liked User Modal *****-->
  </div>
</template>

<script>
import {
  Hooper,
  Slide,
  Progress as HooperProgress,
  Pagination as HooperPagination,
  Navigation as HooperNavigation,
} from "hooper";
import "hooper/dist/hooper.css";
const { io } = require("socket.io-client");

export default {
  components: {
    Hooper,
    Slide,
    HooperProgress,
    HooperPagination,
    HooperNavigation,
  },
  data() {
    return {
      socket: null,

      hooperImage: {
        commentsToShow: 1,
        centerMode: false,
        breakpoints: {
          768: {
            centerMode: false,
            itemsToShow: 2,
          },
        },
      },
      visible: false,
      imgName: "",
      index: "",
      relatedResearch: [],
      details: [],
      likedUser: [],
      post_slug: "",
      post_id: "",
      isPostInfoIndex: 1,
      isLoading: true,
      upVoteCount: 0,
      downVoteCount: 0,
      avgVoteCount: 0,
      authUserVoteCount: "",

      likedUserModal: false,
      limit: 4,
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
      http: this.$config.IMAGE_URL,
    };
  },
  methods: {
    handleView(item, index) {
      this.imgName = this.http + item;
      this.index = index;
      this.visible = true;
    },
    showPostInfo(index) {
      this.isPostInfoIndex = index;
    },

    async upVote() {
      if (
        this.authUser.userType == "teacher" ||
        this.authUser.userType == "admin"
      ) {
        if (this.details.user_id != this.authUser.id) {
          let upVoteCount1 = parseInt(this.upVoteCount, 10);
          let avgVoteCount1 = parseInt(this.avgVoteCount, 10);
          let downVoteCount1 = parseInt(this.downVoteCount, 10);
          if (this.authUserVoteCount == "none") {
            this.upVoteCount = upVoteCount1 + 1;
            this.avgVoteCount = upVoteCount1 + 1 - downVoteCount1;
            this.authUserVoteCount = "up";
          } else if (this.authUserVoteCount == "up") {
            this.upVoteCount = upVoteCount1 - 1;
            this.avgVoteCount = upVoteCount1 - 1 - downVoteCount1;
            this.authUserVoteCount = "none";
          } else if (this.authUserVoteCount == "down") {
            this.upVoteCount = upVoteCount1 + 1;
            this.avgVoteCount = upVoteCount1 + 1 - (downVoteCount1 - 1);
            this.downVoteCount = downVoteCount1 - 1;
            this.authUserVoteCount = "up";
          }

          let obj = {
            id: this.details.id,
            upVote: 1,
          };
          console.log(obj);
          const res = await this.callApi("post", "/api/up_vote", obj);
          // if (res.status == 200) {
          //   this.upVoteCount = upVoteCount1 - 1;
          //   this.avgVoteCount = upVoteCount1 - 1 - downVoteCount1;
          //   this.authUserVoteCount = "none";
          // }
          // if (res.status == 201) {
          //   this.upVoteCount = upVoteCount1 + 1;
          //   this.avgVoteCount = upVoteCount1 + 1 - (downVoteCount1 - 1);
          //   this.downVoteCount = downVoteCount1 - 1;
          //   this.authUserVoteCount = "up";
          // }
          // if (res.status == 202) {
          //   this.upVoteCount = upVoteCount1 + 1;
          //   this.avgVoteCount = upVoteCount1 + 1 - downVoteCount1;
          //   this.authUserVoteCount = "up";
          // }
          let notificationObj = {
            id: this.details.user_id,
          };

          this.socket.emit("notification", notificationObj);
        } else {
          this.i("You can't vote your own post!");
        }
      } else {
        this.i(
          "Thanks for the feedback! You are not eligible to cast a vote, but your feedback has been recorded."
        );
      }
    },
    async downVote() {
      if (
        this.authUser.userType == "teacher" ||
        this.authUser.userType == "admin"
      ) {
        if (this.details.user_id != this.authUser.id) {
          let upVoteCount1 = parseInt(this.upVoteCount, 10);
          let avgVoteCount1 = parseInt(this.avgVoteCount, 10);
          let downVoteCount1 = parseInt(this.downVoteCount, 10);
          if (this.authUserVoteCount == "down") {
            this.avgVoteCount = upVoteCount1 - (downVoteCount1 - 1);
            this.downVoteCount = downVoteCount1 - 1;
            this.authUserVoteCount = "none";
          } else if (this.authUserVoteCount == "up") {
            this.upVoteCount = upVoteCount1 - 1;
            this.downVoteCount = downVoteCount1 + 1;
            this.avgVoteCount = upVoteCount1 - 1 - (downVoteCount1 + 1);
            this.authUserVoteCount = "down";
          } else if (this.authUserVoteCount == "none") {
            this.avgVoteCount = upVoteCount1 - (downVoteCount1 + 1);
            this.downVoteCount = downVoteCount1 + 1;
            this.authUserVoteCount = "down";
          }
          let obj = {
            id: this.details.id,
            // user_id: authUser.id,
            downVote: 1,
          };
          console.log(obj);
          const res = await this.callApi("post", "/api/down_vote", obj);
          // if (res.status == 200) {
          //   this.avgVoteCount = upVoteCount1 - (downVoteCount1 - 1);
          //   this.downVoteCount = downVoteCount1 - 1;
          //   this.authUserVoteCount = "none";
          // }
          // if (res.status == 201) {
          //   this.upVoteCount = upVoteCount1 - 1;
          //   this.downVoteCount = downVoteCount1 + 1;
          //   this.avgVoteCount = upVoteCount1 - 1 - (downVoteCount1 + 1);
          //   this.authUserVoteCount = "down";
          // }

          // if (res.status == 202) {
          //   this.avgVoteCount = upVoteCount1 - (downVoteCount1 + 1);
          //   this.downVoteCount = downVoteCount1 + 1;
          //   this.authUserVoteCount = "down";
          // }
          let notificationObj = {
            id: this.details.user_id,
          };

          this.socket.emit("notification", notificationObj);
        } else {
          this.i("You can't vote your own post!");
        }
      } else {
        this.i(
          "Thanks for the feedback! You are not eligible to cast a vote, but your feedback has been recorded."
        );
      }
    },

    async like() {
      if (this.details.user_id != this.authUser.id) {
        let obj = {
          id: this.details.id,
        };
        this.id = this.details.id;
        console.log(this.id);
        if (this.details.authUserLike == "no") {
          this.details.like_count += 1;
          this.details.authUserLike = "yes";
        } else {
          this.details.like_count -= 1;
          this.details.authUserLike = "no";
        }
        let notificationObj = {
          id: this.details.user_id,
        };

        const res = await this.callApi("post", "/api/like", obj);
        // if (res.status == 201) {
        this.socket.emit("notification", notificationObj);
        // }
      } else {
        this.i("You can't like your own post!!");
      }
    },

    resizeTextarea(e) {
      let area = e.target;
      area.style.height = "auto";
      area.style.overflow = "hidden";
      area.style.height = area.scrollHeight + "px";
      // this.showbtn = true;
    },

    async getLikedUser() {
      let obj = {
        id: this.details.id,
      };
      console.log(this.details.id);
      const res = await this.callApi(
        "get",
        `/api/get_liked_user?id=${this.details.id}`
      );
      if (res.status == 200) {
        this.likedUser = res.data.data;
        this.likedUserModal = true;
      } else {
        this.swr();
      }
    },

    async getRelatedResearch() {
      this.post_slug = this.$route.params.slug;

      const res = await this.callApi(
        "get",
        `/api/get_related_research?slug=${this.post_slug}&type=${this.details.type}&limit=${this.limit}`
      );
      if (res.status == 200) {
        this.relatedResearch = res.data.data;
      } else {
        this.swr();
      }
    },
    async getDetails() {
      this.post_slug = this.$route.params.slug;

      this.isLoading = true;
      const res = await this.callApi(
        "get",
        `/api/post_details/${this.post_slug}`
      );

      if (res.status == 200) {
        this.details = res.data.data[0];
        this.upVoteCount = this.details.upVote;
        this.downVoteCount = this.details.downVote;
        this.avgVoteCount = this.details.avgVote;
        this.authUserVoteCount = this.details.authUserVote;
        this.post_id = this.details.id;
        this.getRelatedResearch();

        if (this.authUser) {
          const res1 = await this.callApi(
            "post",
            `/api/read/${this.details.id}`
          );
        }
      } else {
        this.swr();
      }

      this.isLoading = false;
    },
  },
  watch: {
    "$route.params.slug"(oldValue, newValue) {
      if (oldValue != newValue) {
        console.log("route is changing!");
        this.getDetails();
      }
    },
  },
  async created() {
    // this.token = window.Laravel.csrfToken;
    this.getDetails();
  },
  mounted() {
    this.socket = io("http://localhost:5000", {
      methods: ["GET", "POST"],
      transports: ["websocket"],
      credentials: true,
    });
  },
  // beforeDestroy() {
  //     document.removeEventListener("click", this.hideButton);
  // },
};
</script>

<style lang="scss">
.slide {
  &-enter {
    overflow: hidden;
    max-height: 0;
    &-to {
      max-height: 500px;
      overflow: hidden;
    }
    &-active {
      -moz-transition-duration: 0.5s;
      -webkit-transition-duration: 0.5s;
      -o-transition-duration: 0.5s;
      transition-duration: 0.5s;
      -moz-transition-timing-function: ease-in;
      -webkit-transition-timing-function: ease-in;
      -o-transition-timing-function: ease-in;
      transition-timing-function: ease-in;
    }
  }
  &-leave {
    @extend .slide-enter-to;
    &-to {
      @extend .slide-enter;
    }
    &-active {
      -moz-transition-duration: 0.5s;
      -webkit-transition-duration: 0.5s;
      -o-transition-duration: 0.5s;
      transition-duration: 0.5s;
      -moz-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      -webkit-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      -o-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
    }
  }
}
</style>
<style lang="scss">
.slide {
  &-enter {
    overflow: hidden;
    max-height: 0;
    &-to {
      max-height: 500px;
      overflow: hidden;
    }
    &-active {
      -moz-transition-duration: 0.5s;
      -webkit-transition-duration: 0.5s;
      -o-transition-duration: 0.5s;
      transition-duration: 0.5s;
      -moz-transition-timing-function: ease-in;
      -webkit-transition-timing-function: ease-in;
      -o-transition-timing-function: ease-in;
      transition-timing-function: ease-in;
    }
  }
  &-leave {
    @extend .slide-enter-to;
    &-to {
      @extend .slide-enter;
    }
    &-active {
      -moz-transition-duration: 0.5s;
      -webkit-transition-duration: 0.5s;
      -o-transition-duration: 0.5s;
      transition-duration: 0.5s;
      -moz-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      -webkit-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      -o-transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
      transition-timing-function: cubic-bezier(0, 1, 0.5, 1);
    }
  }
}
</style>
