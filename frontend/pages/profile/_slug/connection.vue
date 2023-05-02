<template>
  <div>
    <div v-if="isLoading" class="loader-lg">
      <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
    </div>
    <div v-else-if="!isLoading && connection == ''">
      <div class="_card"><h1>No Connection Found</h1></div>
    </div>
    <div class="connection--item" v-else>
      <h5 class="post-title">Connections</h5>
      <ul>
        <li v-for="(connection, index) in connection">
          <nuxt-link
            class="content"
            v-if="user_slug == connection.user1.slug"
            :to="`/profile/${connection.user2.slug}/overview`"
          >
            <div class="content--image">
              <img :src="connection.user2.image" />
            </div>
            <div>
              <h4>{{ connection.user2.name }}</h4>
              <p>{{ connection.user2.designation }}</p>
            </div>
          </nuxt-link>
          <nuxt-link
            class="content"
            v-else-if="user_slug == connection.user2.slug"
            :to="`/profile/${connection.user1.slug}/overview`"
          >
            <div class="content--image">
              <img :src="connection.user1.image" />
            </div>
            <div>
              <h4>{{ connection.user1.name }}</h4>
              <p>{{ connection.user1.designation }}</p>
            </div>
          </nuxt-link>
          <!-- <button
            class="main-btn main-btn__bg"
            v-if="user.status == 'pending'"
            @click="ignoreConnection(index)"
          >
            <i class="fa-solid fa-clock-rotate-left"></i>
            Pending
          </button>
          <button
            class="main-btn main-btn__border"
            @click="connect(index)"
            v-else-if="user.status == 'connect'"
          >
            <i class="fa-solid fa-user-plus"></i>
            Connect
          </button> -->
          <!-- <button class="d-md-none d-sm-block btn btn__icon">
            <i class="fa-solid fa-user-check"></i>
          </button> -->
          <button class="d-none d-md-block btn btn__border">
            <i class="fa-solid fa-user-check"></i>
            Connected
          </button>
        </li>
      </ul>
    </div>
  </div>
</template>

<script>
import { mapGetters } from "vuex";

export default {
  middleware: "auth",

  components: {},
  data() {
    return {
      loadMoreLoading: false,
      noPostRemaining: false,
      limit: 5,
      user_slug: this.$route.params.slug,
    };
  },
  computed: {
    ...mapGetters({
      connection: "getConnectionItem",
      isLoading: "getGlobalPostLoading",
    }),
  },
  methods: {
    async getConnection() {
      this.page = this.$route.query.page ? this.$route.query.page : 1;

      this.$store.commit("setGlobalPostLoading", true);
      const connection = await this.callApi(
        "get",
        `/api/get_user_connection?slug=${this.user_slug}&limit=${this.limit}`
      );

      if (connection.status == 200) {
        this.$store.commit("updateConnection", connection.data.data);
        // if (connection.data.data.length < 6)
        //   this.noConnectionDataRemaining = true;
      }
      this.$store.commit("setGlobalPostLoading", false);
    },
    async loadMore(more) {
      console.log("Load more is calling! length", this.connection.length);

      if (this.noPostRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_user_connection?slug=${this.user_slug}&limit=${this.limit}`
      );
      if (res.status == 200) {
        let prevLength = this.connection.length;
        if (this.connection.length == res.data.data.length) {
          this.noPostRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.$store.commit("pushConnection", d);
          }
        }
      }
      this.loadMoreLoading = false;
      console.log("Load more is finished! length", this.connection.length);
    },
  },
  async created() {
    this.getConnection();
  },
  mounted() {
    // document.addEventListener("click", this.hideSearchbar);
    window.onscroll = () => {
      this.bottomOfWindow =
        window.pageYOffset + window.innerHeight >
        document.body.scrollHeight - 100;

      if (this.bottomOfWindow) {
        if (!this.loadMoreLoading) {
          this.loadMore(5);
        }
      }
    };
  },
};
</script>

<style></style>
