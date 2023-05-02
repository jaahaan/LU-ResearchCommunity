<template>
  <div class="chat col-lg-8">
    <div class="chat-section">
      <div class="menu">
        <div class="menu--header">
          <p>Chats</p>
          <!-- <div class="user">
            <img src="/assets/profileImages/download.jpg" alt="" />
            <span>Name</span>
          </div> -->
        </div>
        <div class="menu--search">
          <div class="searchForm">
            <input type="text" placeholder="Find a user" v-model="keyword" />
          </div>
          <div
            class="menu--list"
            v-bind:class="{
              isActive: isActive,
            }"
          >
            <ul
              v-if="
                Users.length > 0 && keyword.length > 0 && authUser.id != user.id
              "
              :key="user.id"
              v-for="(user, index) in Users"
            >
              <li class="menu--list---item" @click="handleSelect(index)">
                <div class="menu-link">
                  <img :src="user.image" alt="" />
                  <h4>{{ user.name }}</h4>
                </div>
              </li>
            </ul>
          </div>
        </div>
        <div class="menu--list" ref="scrollConv">
          <ul
            v-if="conversations.length > 0"
            v-for="(user, index) in conversations"
            :key="index"
          >
            <li
              class="menu--list---item"
              v-if="user.from_id == authUser.id"
              @click="getSelectedUserChat(user.to_user, user.id)"
            >
              <div
                class="menu-link"
                v-bind:class="{
                  active: selectedUserInfo.room_id == user.id,
                }"
              >
                <Tooltip
                  :content="user.to_user.name"
                  placement="right"
                  class="d-md-none d-sm-block"
                >
                  <img :src="user.to_user.image" alt=""
                /></Tooltip>
                <img
                  :src="user.to_user.image"
                  alt=""
                  class="d-none d-md-block"
                />
                <div>
                  <h4>{{ user.to_user.name }}</h4>
                  <p v-if="user.latest_message !== null">
                    {{ user.latest_message.msg }}
                  </p>
                </div>
              </div>
            </li>
            <li
              class="menu--list---item"
              v-if="user.to_id == authUser.id"
              @click="getSelectedUserChat(user.from_user, user.id)"
            >
              <div
                class="menu-link"
                v-bind:class="{
                  active: selectedUserInfo.room_id == user.id,
                }"
              >
                <Tooltip
                  :content="user.from_user.name"
                  placement="right"
                  class="d-md-none d-sm-block"
                >
                  <img :src="user.from_user.image" alt=""
                /></Tooltip>
                <img
                  :src="user.from_user.image"
                  alt=""
                  class="d-none d-md-block"
                />
                <div>
                  <h4>{{ user.from_user.name }}</h4>
                  <p v-if="user.latest_message !== null">
                    {{ user.latest_message.msg }}
                  </p>
                </div>
              </div>
            </li>
          </ul>
          <div
            v-if="loadMoreConversationLoading && !noConversationRemaining"
            class="loader-sm"
          >
            <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
          </div>
        </div>
      </div>
      <div
        class="menu-item"
        v-if="isActive"
        v-bind:class="{
          isActive: isActive,
        }"
      >
        <div class="menu-item--header">
          <img :src="this.selectedUserInfo.selectedUserImage" alt="" />
          <div>
            <h1>{{ this.selectedUserInfo.selectedUserName }}</h1>
            <p v-if="isTyping">Typing...</p>
          </div>
        </div>

        <div class="menu-item--box" ref="scrollToMe">
          <!-- <div v-if="loadMoreChatLoading && !noChatRemaining" class="loader-sm">
            <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
          </div> -->
          <div v-if="messages.length > 0">
            <div
              v-for="msg in messages"
              v-if="msg.room_id == selectedUserInfo.room_id"
            >
              <div class="message">
                <!-- <div class="messageInfo">
                <img :src="msg.image" alt="" />
                <span>just now</span>
              </div> -->
                <div v-if="msg.from_id == authUser.id">
                  <div class="messageContentRight">
                    <!-- <a>{{ msg.name }}</a> -->

                    <p>{{ msg.msg }}</p>

                    <!-- <img src="/assets/profileImages/download.jpg" alt="" /> -->
                  </div>
                </div>
                <div class="messageContentLeft" v-else>
                  <!-- <a>{{ msg.from_user.name }}</a> -->

                  <p>{{ msg.msg }}</p>

                  <!-- <img src="/assets/profileImages/download.jpg" alt="" /> -->
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="menu-item--input">
          <input
            type="text"
            placeholder="Type something..."
            v-model="data.msg"
            v-on:keyup="typingHandler"
            v-on:keyup.enter="sendMsg"
          />
          <div class="send">
            <Icon type="md-send" @click="sendMsg" />
          </div>
        </div>
      </div>
      <div class="menu-item" v-else>
        <div class="menu-item--header"></div>
        <div class="text-center">
          <h2>Select a user to chat</h2>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
const { io } = require("socket.io-client");
import { mapGetters } from "vuex";

export default {
  middleware: "auth",

  data() {
    return {
      isActive: false,
      loadMoreConversationLoading: false,
      loadMoreChatLoading: false,
      noChatRemaining: false,
      noConversationRemaining: false,
      data: {
        msg: "",
      },
      Users: [],
      keyword: "",
      conversations: [],
      selectedUserChat: [],
      selectedChat: [],
      room_id: "",
      selectedUserId: "",
      selectedUserImage: "",
      selectedUserSlug: "",
      selectedUserName: "",
      index: -1,
      limit: 6,
      socketConnected: false,
      isTyping: false,
      selectedChatCompare: "",
      notification: "",
      socket: null,
    };
  },
  computed: {
    ...mapGetters({
      selectedUserInfo: "getSelectedUserInfo",
      messages: "getMessages",
      isLoading: "getGlobalPostLoading",
      unseenMsgCount: "getUnseenMsgCount",
    }),
  },
  watch: {
    keyword(after, before) {
      this.getResults();
    },
  },
  methods: {
    async getResults() {
      const res = await this.callApi(
        "get",
        `/api/search?keyword=${this.keyword}&limit=${this.limit}`
      );
      if (res.status == 200) {
        this.Users = res.data;
      } else {
        this.swr();
      }
    },
    async handleSelect(index) {
      console.log(this.conversations);
      let info = {
        selectedUserId: this.Users[index].id,
        selectedUserImage: this.Users[index].image,
        selectedUserSlug: this.Users[index].slug,
        selectedUserName: this.Users[index].name,
      };
      let user = {
        id: this.Users[index].id,
        image: this.Users[index].image,
        slug: this.Users[index].slug,
        name: this.Users[index].name,
      };
      this.$store.commit("setSelectedUserInfo", info);
      this.isActive = true;
      let obj = {
        from_id: this.authUser.id,
        to_id: this.Users[index].id,
      };
      const res = await this.callApi("post", `/api/add_conversation`, obj);
      if (res.status == 200) {
        this.conversations.unshift(res.data.data[0]);
        this.getSelectedUserChat(user, res.data.data[0].id);
        // this.Users = [];
        this.keyword = "";
      } else if (res.status == 201) {
        // this.conversations.push(res.data.data[0]);
        this.getSelectedUserChat(user, res.data.data[0].id);
        // this.Users = [];
        this.keyword = "";
      }
    },
    handleUserScroll(e) {
      const scrollTop = e.target.scrollTop;
      const scrollHeight = e.target.scrollHeight;
      const elementHeight = e.target.offsetHeight;
      if (scrollTop === 0 && elementHeight < scrollHeight) {
        this.loadMoreChats(5);
      }
    },
    scrollToEnd() {
      const el = this.$refs.scrollToMe;

      if (el) {
        // Use el.scrollIntoView() to instantly scroll to the element
        el.scrollTop = el.scrollHeight + 120;
        el.onscroll = () => {
          const scrollTop = el.scrollTop;
          const scrollHeight = el.scrollHeight;
          const elementHeight = window.pageYOffset;
          if (scrollTop === 0 && elementHeight < scrollHeight) {
            if (!this.loadMoreChatLoading) {
              this.loadMoreChats(5);
            }
          }
        };
      }
    },
    async getSelectedUserChat(user, index) {
      let info = {
        room_id: index,
        selectedUserId: user.id,
        selectedUserImage: user.image,
        selectedUserSlug: user.slug,
        selectedUserName: user.name,
      };
      this.$store.commit("setSelectedUserInfo", info);

      let roomId = index;
      this.isActive = true;
      this.selectedChatCompare = this.selectedUserInfo;
      // window.history.pushState({}, null, `${this.$route.path}`);
      this.$store.commit("setGlobalPostLoading", true);
      const response = await this.callApi(
        "get",
        `/api/get_chat?limit=${3}&roomId=${roomId}`
      );
      if (response.status == 200) {
        this.$store.commit("setMessages", response.data.data);
        this.socket.emit("join chat", roomId);
      } else this.swr();
      this.$store.commit("setGlobalPostLoading", false);
    },
    async loadMoreChats(more) {
      console.log("Load more is calling! length", this.messages.length);

      if (this.noChatRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreChatLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_chat?limit=${this.limit}&roomId=${this.selectedUserInfo.room_id}`
      );
      if (res.status == 200) {
        let prevLength = this.messages.length;
        if (this.messages.length == res.data.data.length) {
          this.noChatRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.messages.push(d);
            // this.$store.commit("pushAllGlobalPost", d);
          }
        }
      }
      this.loadMoreChatLoading = false;
      console.log("Load more is finished! length", this.messages.length);
    },

    async typingHandler() {
      // if (!this.socketConnected) return;

      if (!this.isTyping) {
        console.log("typing");
        this.isTyping = true;
        this.socket.emit("typing", this.selectedUserInfo.room_id);
      }
      let lastTypingTime = new Date().getTime();
      var timerLength = 3000;
      setTimeout(() => {
        var timeNow = new Date().getTime();
        var timeDiff = timeNow - lastTypingTime;
        if (timeDiff >= timerLength && this.isTyping) {
          this.socket.emit("stop typing", this.selectedUserInfo.room_id);
          this.isTyping = false;
        }
      }, timerLength);
    },
    async sendMsg() {
      if (this.data.msg) {
        this.socket.emit("stop typing", this.selectedUserInfo.room_id);
        if (this.data.msg.trim() == "") return;
        const msg = this.data.msg;
        let obj2 = {
          room_id: this.selectedUserInfo.room_id,
          to_id: this.selectedUserInfo.selectedUserId,
        };
        let obj1 = {
          room_id: this.selectedUserInfo.room_id,
          from_id: this.authUser.id,
          to_id: this.selectedUserInfo.selectedUserId,
          msg: this.data.msg,
          image: "",
        };
        let obj = {
          room_id: this.selectedUserInfo.room_id,
          from_id: this.authUser.id,
          to_id: this.selectedUserInfo.selectedUserId,
          image: this.authUser.image,
          name: this.authUser.name,
          msg: this.data.msg,
        };
        this.messages.push(obj);
        this.data.msg = "";

        const res = await this.callApi("post", `/api/add_chat`, obj1);

        if (res.status == 200) {
          let obj3 = {
            room_id: this.selectedUserInfo.room_id,
            from_id: this.authUser.id,
            to_id: this.selectedUserInfo.selectedUserId,
            image: this.authUser.image,
            name: this.authUser.name,
            msg: msg,
            chat: res.data.data,
          };
          this.socket.emit("new message", obj3);
        }
      }
    },

    async getConversations() {
      const res = await this.callApi(
        "get",
        `/api/get_conversation?limit=${this.limit}`
      );
      if (res.status == 200) {
        this.conversations = res.data.data;
      }
    },
    async loadMoreConversations(more) {
      console.log("Load more is calling! length", this.conversations.length);

      if (this.noConversationRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreConversationLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_conversation?limit=${this.limit}`
      );

      if (res.status == 200) {
        let prevLength = this.conversations.length;
        if (this.conversations.length == res.data.data.length) {
          this.noConversationRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.conversations.push(d);
            // this.$store.commit("pushAllGlobalPost", d);
          }
        }
      }
      this.loadMoreConversationLoading = false;
      console.log("Load more is finished! length", this.conversations.length);
    },
    async callUnseenMsgCount(newMessageRecieved) {
      // const room_id = this.notification.room_id;
      console.log("newMessageRecieved" + newMessageRecieved);
      const res = await this.callApi(
        "get",
        `/api/add_unseenmsg_count`,
        newMessageRecieved
      );

      // if (res.status == 200) {
      this.$store.dispatch("updateUnseenMsgCount", res.data.count);
      // }
    },
  },
  async mounted() {
    this.socket = io("http://localhost:5000", {
      methods: ["GET", "POST"],
      transports: ["websocket"],
      credentials: true,
    });
    // this.socket.on("sendChatToClient", (data) => {
    //   if (data.room_id == this.selectedUserInfo.room_id) {
    //     this.$store.commit("pushMessages", data);
    //   } else {
    //     this.callUnseenMsgCount();
    //   }
    // });

    this.socket.emit("setup", this.authUser);
    this.socket.on("connected", () => (this.socketConnected = true));
    this.socket.on("typing", () => (this.isTyping = true));
    this.socket.on("stop typing", () => (this.isTyping = false));
    this.socket.on("message recieved", (newMessageRecieved) => {
      if (
        !this.selectedChatCompare || // if chat is not selected or doesn't match current chat
        this.selectedChatCompare.room_id !== newMessageRecieved.room_id
      ) {
        console.log("inside if");
        if (!this.notification.includes(newMessageRecieved)) {
          // this.notification = newMessageRecieved;
          this.callUnseenMsgCount(newMessageRecieved);
        }
      } else {
        console.log("inside else");

        this.messages.push(newMessageRecieved);
      }
    });
    const el = this.$refs.scrollConv;
    el.onscroll = () => {
      this.bottomOfWindow =
        window.pageYOffset + window.innerHeight >
        document.body.scrollHeight - 100;
      if (this.bottomOfWindow) {
        if (!this.loadMoreConversationLoading) {
          this.loadMoreConversations(4);
        }
      }
    };
    if (this.isActive == true) {
      const el1 = this.$refs.scrollToMe;
    }
    this.scrollToEnd();
  },

  updated() {
    // this.$nextTick(() => this.scrollToEnd());
    this.scrollToEnd();
  },
  async created() {
    this.getConversations();

    if (this.selectedUserInfo.selectedUserId) {
      let user = {
        id: this.selectedUserInfo.selectedUserId,
        image: this.selectedUserInfo.selectedUserImage,
        slug: this.selectedUserInfo.selectedUserSlug,
        name: this.selectedUserInfo.selectedUserName,
      };
      let obj = {
        from_id: this.authUser.id,
        to_id: this.selectedUserInfo.selectedUserId,
      };
      const res = await this.callApi("post", `/api/add_conversation`, obj);
      if (res.status == 200) {
        this.conversations.unshift(res.data.data[0]);
        this.getSelectedUserChat(user, res.data.data[0].id);
      } else if (res.status == 201) {
        this.getSelectedUserChat(user, res.data.data[0].id);
      }
    }
    console.log(this.unseenMsgCount);
    if (this.unseenMsgCount > 0) {
      this.$store.dispatch("updateUnseenMsgCount", 0);
      const res = await this.callApi("post", `/api/mark_seen_msg`);
    }
  },
  beforeDestroy() {
    // if (this.isActive == true) {
    //   this.$refs.scrollToMe.removeEventListener(
    //     "scroll",
    //     this.handleUserScroll
    //   );
    // }
  },
};
</script>
