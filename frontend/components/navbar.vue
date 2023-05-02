<template>
  <div>
    <header>
      <div
        class="navbar-mobile--wrapper d-lg-none"
        v-bind:class="{ active: isSidebar }"
      >
        <div class="navbar-mobile">
          <div class="navbar-mobile--head">
            <nuxt-link
              class="nav-link"
              aria-current="page"
              to="/home"
              v-if="authUser"
            >
              <img src="/assets/images/logo.png" alt="Brand" />
            </nuxt-link>
            <nuxt-link class="nav-link" aria-current="page" to="/" v-else>
              <img src="/assets/images/logo.png" alt="Brand" />
            </nuxt-link>
            <button type="button" v-on:click="hideSidebar()">
              <i class="lni lni-close"></i>
            </button>
          </div>
          <ul class="navbar-mobile--body">
            <li class="nav-item">
              <nuxt-link
                class="nav-link"
                aria-current="page"
                to="/home"
                v-if="authUser"
                >Home</nuxt-link
              >
              <nuxt-link class="nav-link" aria-current="page" to="/" v-else
                >Home</nuxt-link
              >
            </li>

            <li class="nav-item">
              <nuxt-link class="nav-link" aria-current="page" to="/research"
                >Research</nuxt-link
              >
            </li>

            <li class="nav-item dropdown">
              <a
                class="nav-link dropdown-toggle"
                id="navbarDropdown"
                role="button"
                data-bs-toggle="dropdown"
                aria-expanded="false"
              >
                Departments
              </a>

              <ul class="dropdown-menu" aria-labelledby="navbarDropdown">
                <li v-for="(department, index) in departmentInfo" :key="index">
                  <nuxt-link
                    class="dropdown-item"
                    :to="`/department/${department.department_name}/${department.id}`"
                    >{{ department.department_name }}</nuxt-link
                  >
                </li>
              </ul>
            </li>
            <!-- <li class="nav-item">
              <nuxt-link
                class="nav-link"
                aria-current="page"
                v-if="authUser.userType == 'teacher'"
                to="/admin/teachers"
                >Add Teacher</nuxt-link
              >
            </li> -->
          </ul>
        </div>
      </div>

      <!-- ****message box**** -->
      <div class="navbar-message--box" v-bind:class="{ active: isChatBox }">
        <div class="menu-item">
          <div class="menu-item--header">
            <div class="menu-item--header--item">
              <img :src="this.selectedUserInfo.selectedUserImage" alt="" />
              <div>
                <h1>{{ this.selectedUserInfo.selectedUserName }}</h1>
                <p v-if="isTyping">Typing...</p>
              </div>
            </div>
            <button type="button" v-on:click="hideChatBox()">
              <i class="lni lni-close"></i>
            </button>
          </div>

          <div class="menu-item--box" ref="scrollToMe">
            <div v-if="messages.length > 0">
              <div
                v-for="msg in messages"
                v-if="msg.room_id == selectedUserInfo.room_id"
              >
                <div class="message">
                  <div v-if="msg.from_id == authUser.id">
                    <div class="messageContentRight">
                      <p>{{ msg.msg }}</p>
                    </div>
                  </div>
                  <div class="messageContentLeft" v-else>
                    <p>{{ msg.msg }}</p>
                  </div>
                </div>
              </div>
            </div>
            <div v-else-if="isChatLoading" class="loader-lg">
              <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
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
      </div>
      <!-- ****message list box**** -->
      <div
        class="navbar-message--dropdown"
        v-bind:class="{ active: isChatListBox }"
      >
        <div class="navbar-message--dropdown--header">
          <p>Chats</p>
        </div>
        <div class="navbar-message--dropdown--input">
          <input
            type="text"
            placeholder="Find a user"
            v-model="keyword"
            ref="chatBoxSearch"
          />

          <div
            class="navbar-message--dropdown--input---item"
            v-if="
              Users.length > 0 && keyword.length > 0 && authUser.id != user.id
            "
            :key="user.id"
            v-for="(user, index) in Users"
            @click="handleSelect(index)"
          >
            <div class="menu-link">
              <div class="menu-link--image">
                <img :src="user.image" alt="" />
              </div>
              <h4>{{ user.name }}</h4>
            </div>
          </div>
        </div>

        <div class="navbar-message--dropdown--list" ref="scrollConv">
          <div v-if="isConversationLoading" class="loader-lg">
            <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
          </div>
          <div
            v-else-if="conversations.length > 0"
            v-for="(user, index) in conversations"
            :key="index"
          >
            <div
              class="navbar-message--dropdown--list---item profile"
              v-if="user.from_id == authUser.id"
              @click="getSelectedUserChat(user.to_user, user.id)"
            >
              <div
                class="menu-link"
                v-bind:class="{
                  active: selectedUserInfo.room_id == user.id,
                }"
              >
                <div class="menu-link--image">
                  <img :src="user.to_user.image" alt="" />
                </div>
                <div>
                  <h4>{{ user.to_user.name }}</h4>
                  <p
                    v-if="user.latest_message !== null"
                    v-bind:class="{
                      unseen:
                        user.is_seen == null &&
                        user.last_msg_to_id == authUser.id,
                    }"
                  >
                    <!-- <i
                                class="las la-check-circle"
                                v-if="user.last_msg_to_id !== authUser.id"
                              ></i> -->
                    {{ user.latest_message.msg }}
                  </p>
                </div>
              </div>
            </div>
            <div
              class="navbar-message--dropdown--list---item"
              v-if="user.to_id == authUser.id"
              @click="getSelectedUserChat(user.from_user, user.id)"
            >
              <div
                class="menu-link"
                v-bind:class="{
                  active: selectedUserInfo.room_id == user.id,
                }"
              >
                <div class="menu-link--image">
                  <img :src="user.from_user.image" alt="img" />
                </div>
                <div>
                  <h4>{{ user.from_user.name }}</h4>
                  <p
                    v-if="user.latest_message !== null"
                    v-bind:class="{
                      unseen:
                        user.is_seen == null &&
                        user.last_msg_to_id == authUser.id,
                    }"
                  >
                    <!-- <i
                                class="las la-check-circle"
                                v-if="user.last_msg_to_id !== authUser.id"
                              ></i> -->
                    {{ user.latest_message.msg }}
                  </p>
                </div>
              </div>
            </div>
          </div>
          <!-- <div v-else-if="isConversationLoading" class="loader-sm">
            <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
          </div> -->
          <div
            v-if="loadMoreConversationLoading && !noConversationRemaining"
            class="loader-sm"
          >
            <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
          </div>
        </div>
      </div>
      <!-- <div class="navbar-message--wrapper" v-bind:class="{ active: isChatBox }">
        <div class="chat">
          <div class="chat-section">
            <div class="menu">
              <div class="menu--header">
                <p>Chats</p>
              </div>
              <div class="menu--search">
                <div class="searchForm">
                  <input
                    type="text"
                    placeholder="Find a user"
                    v-model="keyword"
                  />
                </div>
                <div
                  class="menu--list"
                  v-bind:class="{
                    isActive: isActive,
                  }"
                >
                  <ul
                    v-if="
                      Users.length > 0 &&
                      keyword.length > 0 &&
                      authUser.id != user.id
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
                        <p
                          v-if="user.latest_message !== null"
                          v-bind:class="{ unseen: user.is_seen == null }"
                        >
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
                        <p
                          v-if="user.latest_message !== null"
                          v-bind:class="{ unseen: user.is_seen == null }"
                        >
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
                <div v-if="isLoading" class="loader-lg">
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
                <div class="menu-item--header--item">
                  <img :src="this.selectedUserInfo.selectedUserImage" alt="" />
                  <div>
                    <h1>{{ this.selectedUserInfo.selectedUserName }}</h1>
                    <p v-if="isTyping">Typing...</p>
                  </div>
                </div>
                <button type="button" v-on:click="hideChatBox()">
                  <i class="lni lni-close"></i>
                </button>
              </div>

              <div class="menu-item--box" ref="scrollToMe">
                <div v-if="messages.length > 0">
                  <div
                    v-for="msg in messages"
                    v-if="msg.room_id == selectedUserInfo.room_id"
                  >
                    <div class="message">
                      <div v-if="msg.from_id == authUser.id">
                        <div class="messageContentRight">

                          <p>{{ msg.msg }}</p>

                        </div>
                      </div>
                      <div class="messageContentLeft" v-else>

                        <p>{{ msg.msg }}</p>

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
            <div v-else-if="isChatLoading" class="loader-lg">
              <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
            </div>
            <div class="menu-item" v-else>
              <div class="menu-item--header">
                <div></div>
                <button type="button" v-on:click="hideChatBox()">
                  <i class="lni lni-close"></i>
                </button>
              </div>
              <div class="text-center">
                <h2>Select a user to chat</h2>
              </div>
            </div>
          </div>
        </div>
      </div> -->
      <!-- ****connection box**** -->
      <!-- <div
        class="navbar-notification--wrapper"
        v-bind:class="{ active: isConnectionBox }"
      >
        <div class="navbar-notification">
          <div class="navbar-notification--head">
            <h5>Connections</h5>
            <button type="button" v-on:click="hideConnectionBox()">
              <i class="lni lni-close"></i>
            </button>
          </div>
          <div class="navbar-notification--body">
            <button
              @click="getConnection"
              v-bind:class="{ btnActive: isConnection }"
              class="px-3"
            >
              Connections
            </button>
            <button @click="getRequest" v-bind:class="{ btnActive: isRequest }">
              Requests
            </button>

            <ul v-if="isLoading == true">
              <li class="skeleton nav-link">
                <img />
                <p></p>
              </li>
              <li class="skeleton nav-link">
                <img />
                <p></p>
              </li>
              <li class="skeleton nav-link">
                <img />
                <p></p>
              </li>
              <li class="skeleton nav-link">
                <img />
                <p></p>
              </li>
            </ul>

            <ul
              v-for="(connection, index) in connectionItem"
              v-else-if="
                isLoading == false &&
                connectionItem != undefined &&
                connectionItem.length > 0
              "
            >
              <nuxt-link
                class="nav-item"
                v-if="authUser.id == connection.sent_request_user"
                :to="`/profile/${connection.user2.slug}/overview`"
              >
                <li class="nav-link" v-on:click="hideConnectionBox()">
                  <div class="nav-link--image">
                    <img :src="connection.user2.image" />
                  </div>
                  <div>
                    <p>{{ connection.user2.name }}</p>
                    <p>{{ connection.user2.designation }}</p>
                  </div>
                </li>
              </nuxt-link>
              <nuxt-link
                class="nav-item"
                v-else-if="authUser.id == connection.received_request_user"
                :to="`/profile/${connection.user1.slug}/overview`"
              >
                <li class="nav-link" v-on:click="hideConnectionBox()">
                  <div class="nav-link--image">
                    <img :src="connection.user1.image" />
                  </div>
                  <div>
                    <p>{{ connection.user1.name }}</p>
                    <p>{{ connection.user1.designation }}</p>
                  </div>
                </li>
              </nuxt-link>
            </ul>

            <div v-else>
              <h2 class="mt-5 text-center">No Data Found!!</h2>
            </div>
          </div>
        </div>
      </div> -->
      <div
        class="navbar-notification"
        v-bind:class="{ active: isConnectionBox }"
      >
        <div class="navbar-notification--header">
          <p>Connections</p>
        </div>
        <div class="navbar-notification--button" ref="connectionBoxBtn1">
          <button
            @click="getConnection"
            v-bind:class="{ btnActive: isConnection }"
            class="px-3"
          >
            Connections
          </button>
          <button @click="getRequest" v-bind:class="{ btnActive: isRequest }">
            Requests
          </button>
        </div>
        <div class="navbar-notification--body" ref="scrollConn">
          <ul v-if="isLoading == true">
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
          </ul>
          <ul
            v-for="(connection, index) in connectionItem"
            v-if="
              isLoading == false &&
              connectionItem != undefined &&
              connectionItem.length > 0
            "
          >
            <nuxt-link
              class="nav-item"
              v-if="authUser.id == connection.sent_request_user"
              :to="`/profile/${connection.user2.slug}/overview`"
            >
              <li class="nav-link">
                <div class="nav-link--image">
                  <img :src="connection.user2.image" />
                </div>
                <div>
                  <p>{{ connection.user2.name }}</p>
                  <p>{{ connection.user2.designation }}</p>
                </div>
              </li>
            </nuxt-link>
            <nuxt-link
              class="nav-item"
              v-else-if="authUser.id == connection.received_request_user"
              :to="`/profile/${connection.user1.slug}/overview`"
            >
              <li class="nav-link">
                <div class="nav-link--image">
                  <img :src="connection.user1.image" />
                </div>
                <div>
                  <p>{{ connection.user1.name }}</p>
                  <p>{{ connection.user1.designation }}</p>
                </div>
              </li>
            </nuxt-link>
          </ul>

          <div v-if="connectionItem.length == 0">
            <h2 class="mt-5 text-center">No Data Found!!</h2>
          </div>
          <div ref="connectionBoxBtn2">
            <div class="navbar-notification--body--btn">
              <div
                class="navbar-notification--body--btn__main"
                @click="loadMoreConnection(5)"
                v-if="
                  isLoading == false &&
                  connectionItem.length > 4 &&
                  !loadMoreConnectionLoading &&
                  !noConnectionDataRemaining
                "
              >
                Load More
              </div>
              <div
                v-if="loadMoreConnectionLoading && !noConnectionDataRemaining"
                class="navbar-notification--body--loader"
              >
                <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
              </div>
              <div
                v-if="!loadMoreConnectionLoading && noConnectionDataRemaining"
              >
                <h6 class="text-center">No Connection Remaining!!</h6>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div
        class="navbar-notification"
        v-bind:class="{ active: isNotificationBox }"
      >
        <div class="navbar-notification--header">
          <p>Notification</p>
        </div>
        <div class="navbar-notification--button" ref="notificationBoxBtn1">
          <button @click="getNotification" v-bind:class="{ btnActive: isAll }">
            All
          </button>
          <button
            @click="getReadNotification"
            v-bind:class="{ btnActive: isRead }"
          >
            Read
          </button>
          <button
            @click="getUnreadNotification"
            v-bind:class="{ btnActive: isUnread }"
          >
            Unread
          </button>
        </div>
        <div class="navbar-notification--body" ref="scrollNotification">
          <ul v-if="isLoading == true">
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
            <li class="skeleton nav-link">
              <img />
              <p></p>
            </li>
          </ul>
          <div v-if="isLoading == false && notificationItem.length == 0">
            <h2 class="mt-5 text-center">No Notification Found!!</h2>
          </div>
          <ul
            v-for="(notification, index) in notificationItem"
            v-if="
              isLoading == false &&
              notificationItem != undefined &&
              notificationItem.length > 0
            "
          >
            <nuxt-link
              class="nav-item"
              :to="`/profile/${notification.user_slug}/overview`"
              v-if="
                notification.msg == 'accepted your request' ||
                notification.msg == 'requested to connect you'
              "
            >
              <li
                class="nav-link"
                @click="markAsRead(index)"
                v-bind:class="{
                  active: notification.read_at == null,
                }"
              >
                <div>
                  <div class="nav-link--image">
                    <img :src="notification.user_image" />
                  </div>
                  <span class="nav-action nav-action__like"
                    ><i class="fa-solid fa-user-group"></i
                  ></span>
                </div>
                <div>
                  <nuxt-link
                    :to="`/profile/${notification.user_slug}/overview`"
                    >{{ notification.user_name }}</nuxt-link
                  >
                  <span>{{ notification.msg }}</span>
                </div>
              </li>
            </nuxt-link>
            <nuxt-link
              class="nav-item"
              :to="`/description/${notification.post_slug}/comments`"
              v-else-if="
                notification.msg == 'commented your' ||
                notification.msg == 'replied your comment' ||
                notification.msg == 'replied a comment you are following' ||
                notification.msg == 'liked your comment' ||
                notification.msg == 'liked your reply'
              "
            >
              <li
                class="nav-link"
                @click="markAsRead(index)"
                v-bind:class="{
                  active: notification.read_at == null,
                }"
              >
                <div>
                  <div class="nav-link--image">
                    <img :src="notification.user_image" />
                  </div>
                  <span class="nav-action nav-action__like"
                    ><i class="fa-solid fa-comment"></i
                  ></span>
                </div>
                <div v-if="notification.msg == 'commented your'">
                  <nuxt-link
                    :to="`/profile/${notification.user_slug}/overview`"
                    >{{ notification.user_name }}</nuxt-link
                  >
                  {{ notification.msg + " " + notification.post_type }}
                </div>
                <div v-else>
                  <nuxt-link
                    :to="`/profile/${notification.user_slug}/overview`"
                    >{{ notification.user_name }}</nuxt-link
                  >
                  {{ notification.msg }}
                </div>
              </li>
            </nuxt-link>
            <nuxt-link
              class="nav-item"
              :to="`/description/${notification.post_slug}/overview`"
              v-else
            >
              <li
                class="nav-link"
                @click="markAsRead(index)"
                v-bind:class="{
                  active: notification.read_at == null,
                }"
              >
                <div>
                  <div class="nav-link--image">
                    <img :src="notification.user_image" />
                  </div>
                  <span
                    class="nav-action nav-action__like"
                    v-if="notification.msg == 'liked your'"
                    ><i class="fa-solid fa-thumbs-up"></i
                  ></span>
                  <span
                    class="nav-action nav-action__upVote"
                    v-else-if="notification.msg == 'up voted your'"
                    ><i class="fa-solid fa-caret-up"></i
                  ></span>
                  <span
                    class="nav-action nav-action__downVote"
                    v-else-if="notification.msg == 'down voted your'"
                    ><i class="fa-solid fa-caret-down"></i
                  ></span>
                </div>
                <div>
                  <nuxt-link
                    :to="`/profile/${notification.user_slug}/overview`"
                    >{{ notification.user_name }}</nuxt-link
                  >
                  {{ notification.msg + " " + notification.post_type }}
                </div>
              </li>
            </nuxt-link>
          </ul>
          <div ref="notificationBoxBtn2">
            <div class="navbar-notification--body--btn">
              <div
                class="navbar-notification--body--btn__main"
                @click="loadMoreNotification(5)"
                v-if="
                  isLoading == false &&
                  notificationItem.length !== 0 &&
                  notificationItem.length > 4 &&
                  !loadMoreNotificationLoading &&
                  !noNotificationDataRemaining &&
                  isAll
                "
              >
                Load More
              </div>
              <div
                v-if="
                  loadMoreNotificationLoading && !noNotificationDataRemaining
                "
                class="navbar-notification--body--loader"
              >
                <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
              </div>
              <div
                v-if="
                  !loadMoreNotificationLoading && noNotificationDataRemaining
                "
              >
                <h6 class="text-center">No Notification Remaining!!</h6>
              </div>
            </div>
          </div>
        </div>
      </div>
      <!-- ****SearchBox**** -->
      <div
        class="navbar-search"
        v-bind:class="{ active: isSearchbar }"
        ref="searchBox"
      >
        <div class="navbar-search-input">
          <input
            type="search"
            placeholder="Search..."
            v-model="keyword"
            :ref="`search${keyword}`"
          />
          <button type="button" class="search-button">
            <i class="lni lni-search-alt" v-if="keyword == ''"></i>
            <i class="lni lni-close" v-else v-on:click="clearSearchBar()"></i>
          </button>
        </div>

        <div class="navbar-search-cancel">
          <button
            type="button"
            class="cancel-button"
            v-on:click="cancelSearchBar()"
          >
            <i class="lni lni-close"></i>
          </button>
        </div>
        <div
          class="navbar-search-result"
          v-if="Users.length > 0 && keyword.length > 0"
        >
          <ul class="search-list w-100 c-pointer">
            <li
              v-for="user in Users"
              v-if="authUser.id != user.id"
              :key="user.id"
              @click="getSearchedUser(user)"
            >
              <div class="search-list--image">
                <img :src="user.image" />
              </div>
              <div>
                <h4>{{ user.name }}</h4>
                <p>{{ user.designation }}</p>
              </div>
            </li>
            <div
              class="justify-content-center d-flex c-pointer p-3"
              v-if="!loadMoreLoading && Users.length == 3"
              @click="loadMoreUser(3)"
            >
              View more
            </div>
            <div v-if="loadMoreLoading" class="loader-sm">
              <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
            </div>
          </ul>
        </div>
      </div>

      <nav class="navbar navbar-expand-lg">
        <div class="container header-content">
          <div class="navbar-item navbar-itemLogo">
            <nuxt-link class="navbar-brand" to="/home" v-if="authUser"
              ><img src="/assets/images/logo.png" alt="Brand" />
            </nuxt-link>
            <nuxt-link class="navbar-brand" to="/" v-else
              ><img src="/assets/images/logo.png" alt="Brand" />
            </nuxt-link>
          </div>
          <div class="navbar-item navbar-body d-none d-lg-block">
            <ul class="navbar-nav">
              <li class="nav-item">
                <nuxt-link
                  class="nav-link"
                  style="--i: 1"
                  aria-current="page"
                  to="/home"
                  v-if="authUser"
                  >Home</nuxt-link
                >
                <nuxt-link
                  class="nav-link"
                  style="--i: 1"
                  aria-current="page"
                  to="/"
                  v-else
                  >Home</nuxt-link
                >
              </li>

              <li class="nav-item">
                <nuxt-link
                  class="nav-link"
                  style="--i: 2"
                  aria-current="page"
                  to="/research"
                  >Research</nuxt-link
                >
              </li>

              <li class="nav-item dropdown">
                <a
                  class="nav-link dropdown-toggle"
                  id="navbarDropdown"
                  role="button"
                  data-bs-toggle="dropdown"
                  aria-expanded="false"
                  style="--i: 3"
                >
                  Departments
                </a>

                <ul class="dropdown-menu" aria-labelledby="navbarDropdown">
                  <li
                    v-for="(department, index) in departmentInfo"
                    :key="index"
                  >
                    <nuxt-link
                      class="dropdown-item"
                      :to="`/department/${department.department_name}/${department.id}`"
                      >{{ department.department_name }}</nuxt-link
                    >
                  </li>
                </ul>
              </li>
              <!-- <li class="nav-item" v-if="authUser.userType == 'teacher'">
                <nuxt-link
                  class="nav-link"
                  aria-current="page"
                  to="/admin/teachers"
                  style="--i: 4"
                  >Add Teacher</nuxt-link
                >
              </li> -->
            </ul>
          </div>

          <div class="navbar-item">
            <ul class="navbar-item__action" v-if="authUser">
              <li v-on:click="showSearchbar()" ref="searchBoxSource">
                <svg
                  fill="currentColor"
                  viewBox="0 0 16 16"
                  height="19"
                  width="24"
                  class="x1lliihq x1k90msu x2h7rmj x1qfuztq xcza8v6 xlup9mm x1kky2od"
                >
                  <g fill-rule="evenodd" transform="translate(-448 -544)">
                    <g fill-rule="nonzero">
                      <path
                        d="M10.743 2.257a6 6 0 1 1-8.485 8.486 6 6 0 0 1 8.485-8.486zm-1.06 1.06a4.5 4.5 0 1 0-6.365 6.364 4.5 4.5 0 0 0 6.364-6.363z"
                        transform="translate(448 544)"
                      ></path>
                      <path
                        d="M10.39 8.75a2.94 2.94 0 0 0-.199.432c-.155.417-.23.849-.172 1.284.055.415.232.794.54 1.103a.75.75 0 0 0 1.112-1.004l-.051-.057a.39.39 0 0 1-.114-.24c-.021-.155.014-.356.09-.563.031-.081.06-.145.08-.182l.012-.022a.75.75 0 1 0-1.299-.752z"
                        transform="translate(448 544)"
                      ></path>
                      <path
                        d="M9.557 11.659c.038-.018.09-.04.15-.064.207-.077.408-.112.562-.092.08.01.143.034.198.077l.041.036a.75.75 0 0 0 1.06-1.06 1.881 1.881 0 0 0-1.103-.54c-.435-.058-.867.018-1.284.175-.189.07-.336.143-.433.2a.75.75 0 0 0 .624 1.356l.066-.027.12-.061z"
                        transform="translate(448 544)"
                      ></path>
                      <path
                        d="m13.463 15.142-.04-.044-3.574-4.192c-.599-.703.355-1.656 1.058-1.057l4.191 3.574.044.04c.058.059.122.137.182.24.249.425.249.96-.154 1.41l-.057.057c-.45.403-.986.403-1.411.154a1.182 1.182 0 0 1-.24-.182zm.617-.616.444-.444a.31.31 0 0 0-.063-.052c-.093-.055-.263-.055-.35.024l.208.232.207-.206.006.007-.22.257-.026-.024.033-.034.025.027-.257.22-.007-.007zm-.027-.415c-.078.088-.078.257-.023.35a.31.31 0 0 0 .051.063l.205-.204-.233-.209z"
                        transform="translate(448 544)"
                      ></path>
                    </g>
                  </g>
                </svg>
              </li>
              <li v-on:click="showChatListBox()" ref="chatBoxSource">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  viewBox="0 0 24 24"
                  data-supported-dps="24x24"
                  fill="currentColor"
                  class="mercado-match"
                  width="24"
                  height="24"
                  focusable="false"
                >
                  <path
                    d="M16 4H8a7 7 0 000 14h4v4l8.16-5.39A6.78 6.78 0 0023 11a7 7 0 00-7-7zm-8 8.25A1.25 1.25 0 119.25 11 1.25 1.25 0 018 12.25zm4 0A1.25 1.25 0 1113.25 11 1.25 1.25 0 0112 12.25zm4 0A1.25 1.25 0 1117.25 11 1.25 1.25 0 0116 12.25z"
                  ></path>
                </svg>
                <span
                  class="navbar-item__action__badge"
                  v-if="this.unseenMsgCount > 0"
                  >{{ this.unseenMsgCount }}</span
                >
              </li>
              <li v-on:click="showConnectionBox()" ref="connectionBoxSource">
                <svg
                  viewBox="0 0 28 28"
                  class="x1lliihq x1k90msu x2h7rmj x1qfuztq xcza8v6"
                  fill="currentColor"
                  height="24"
                  width="24"
                >
                  <path
                    d="M10.5 4.5c-2.272 0-2.75 1.768-2.75 3.25C7.75 9.542 8.983 11 10.5 11s2.75-1.458 2.75-3.25c0-1.482-.478-3.25-2.75-3.25zm0 8c-2.344 0-4.25-2.131-4.25-4.75C6.25 4.776 7.839 3 10.5 3s4.25 1.776 4.25 4.75c0 2.619-1.906 4.75-4.25 4.75zm9.5-6c-1.41 0-2.125.841-2.125 2.5 0 1.378.953 2.5 2.125 2.5 1.172 0 2.125-1.122 2.125-2.5 0-1.659-.715-2.5-2.125-2.5zm0 6.5c-1.999 0-3.625-1.794-3.625-4 0-2.467 1.389-4 3.625-4 2.236 0 3.625 1.533 3.625 4 0 2.206-1.626 4-3.625 4zm4.622 8a.887.887 0 00.878-.894c0-2.54-2.043-4.606-4.555-4.606h-1.86c-.643 0-1.265.148-1.844.413a6.226 6.226 0 011.76 4.336V21h5.621zm-7.122.562v-1.313a4.755 4.755 0 00-4.749-4.749H8.25A4.755 4.755 0 003.5 20.249v1.313c0 .518.421.938.937.938h12.125c.517 0 .938-.42.938-.938zM20.945 14C24.285 14 27 16.739 27 20.106a2.388 2.388 0 01-2.378 2.394h-5.81a2.44 2.44 0 01-2.25 1.5H4.437A2.44 2.44 0 012 21.562v-1.313A6.256 6.256 0 018.25 14h4.501a6.2 6.2 0 013.218.902A5.932 5.932 0 0119.084 14h1.861z"
                  ></path>
                </svg>
              </li>
              <li
                v-on:click="showNotificationBox()"
                ref="notificationBoxSource"
              >
                <svg
                  viewBox="0 0 28 28"
                  alt=""
                  class="x1lliihq x1k90msu x2h7rmj x1qfuztq x198g3q0"
                  fill="currentColor"
                  height="24"
                  width="24"
                >
                  <path
                    d="M7.847 23.488C9.207 23.488 11.443 23.363 14.467 22.806 13.944 24.228 12.581 25.247 10.98 25.247 9.649 25.247 8.483 24.542 7.825 23.488L7.847 23.488ZM24.923 15.73C25.17 17.002 24.278 18.127 22.27 19.076 21.17 19.595 18.724 20.583 14.684 21.369 11.568 21.974 9.285 22.113 7.848 22.113 7.421 22.113 7.068 22.101 6.79 22.085 4.574 21.958 3.324 21.248 3.077 19.976 2.702 18.049 3.295 17.305 4.278 16.073L4.537 15.748C5.2 14.907 5.459 14.081 5.035 11.902 4.086 7.022 6.284 3.687 11.064 2.753 15.846 1.83 19.134 4.096 20.083 8.977 20.506 11.156 21.056 11.824 21.986 12.355L21.986 12.356 22.348 12.561C23.72 13.335 24.548 13.802 24.923 15.73Z"
                  ></path>
                </svg>
                <span
                  class="navbar-item__action__badge"
                  v-if="this.seenCount > 0"
                  >{{ this.seenCount }}</span
                >
              </li>
              <li class="profile">
                <div
                  class="image"
                  v-on:click="showProfileBox()"
                  ref="profileImageSource"
                >
                  <img :src="`${http + authUser.image}`" alt="img" />
                </div>
                <div
                  class="navbar-message--dropdown"
                  v-bind:class="{ active: isProfileBox }"
                  ref="profileBoxSource"
                >
                  <div class="navbar-message--dropdown--list">
                    <div class="navbar-message--dropdown--list---item profile">
                      <nuxt-link
                        class="menu-link active"
                        :to="`/profile/${authUser.slug}/overview`"
                      >
                        <div class="menu-link--image">
                          <img :src="`${http + authUser.image}`" alt="" />
                        </div>
                        <div>
                          <h4>{{ authUser.name }}</h4>
                          <p>
                            {{ authUser.designation }}
                          </p>
                        </div>
                      </nuxt-link>
                    </div>
                    <div v-if="authUser.userType == 'admin'">
                      <div
                        class="navbar-message--dropdown--list---item profile"
                      >
                        <nuxt-link class="menu-link" to="/admin/teachers">
                          <i class="fa-solid fa-user-tie"></i>
                          <h4>Faculty Members</h4>
                        </nuxt-link>
                      </div>
                      <!-- <div
                        class="navbar-message--dropdown--list---item profile"
                      >
                        <nuxt-link class="menu-link" to="/admin/banners">
                          <i class="fa-solid fa-image"></i>
                          <h4>Banners</h4>
                        </nuxt-link>
                      </div> -->
                    </div>
                    <!-- <div class="navbar-message--dropdown--list---item profile">
                      <nuxt-link class="menu-link" to="/auth/change_password">
                        <i class="fa-solid fa-key"></i>
                        <h4>Change Password</h4>
                      </nuxt-link>
                    </div>
                    <div class="navbar-message--dropdown--list---item profile">
                      <nuxt-link class="menu-link" to="/auth/twoFactorAuth">
                        <i class="fa-solid fa-shield-halved"></i>
                        <div>
                          <h4>Use two-factor authentication</h4>
                          <p>On</p>
                        </div>
                      </nuxt-link>
                    </div> -->
                    <div class="navbar-message--dropdown--list---item profile">
                      <nuxt-link class="menu-link" to="/settings/account">
                        <i class="fa-solid fa-gear"></i>
                        <h4>Settings</h4>
                      </nuxt-link>
                    </div>

                    <div class="navbar-message--dropdown--list---item profile">
                      <a class="menu-link" @click="logout">
                        <i class="fa-solid fa-right-from-bracket"></i>
                        <h4>Log Out</h4>
                      </a>
                    </div>
                  </div>
                </div>
              </li>

              <li v-on:click="showSidebar()" class="d-lg-none">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="25"
                  height="25"
                  fill="currentColor"
                  class="bi bi-list"
                  viewBox="0 0 16 16"
                >
                  <path
                    fill-rule="evenodd"
                    d="M2.5 12a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5z"
                  />
                </svg>
              </li>
            </ul>
            <ul class="navbar-item__action" v-else>
              <li class="profile">
                <nuxt-link class="nav-link" to="/login">Login</nuxt-link>
              </li>
              <li class="profile">
                <nuxt-link class="nav-link" to="/register">Register</nuxt-link>
              </li>
              <li v-on:click="showSidebar()" class="d-lg-none">
                <i class="fa-solid fa-bars"></i>
              </li>
            </ul>
          </div>
        </div>
      </nav>
    </header>
    <Modal
      v-model="isPassChangeModal"
      v-if="isGlobalPostLoading == false"
      :closable="false"
    >
      <div class="research-post--item" id="modal">
        <h5 class="post-title">
          <div>Change Password</div>
          <div class="btn-edit text-danger" @click="closeModal">
            <i class="fa-solid fa-xmark"></i>
          </div>
        </h5>
        <Form label-position="top">
          <FormItem label="Old Password *">
            <Input
              v-model="data.old_password"
              placeholder="Old Password"
              type="password"
            ></Input>
            <span class="text-danger" v-if="errors.old_password">{{
              errors.old_password
            }}</span>
            <span class="text-danger" v-if="errmsg">{{ errmsg }}</span>
          </FormItem>
          <FormItem label="New Password *">
            <Input
              placeholder="New Password"
              v-model="data.password"
              type="password"
            />
            <span class="text-danger" v-if="errors.password">{{
              errors.password
            }}</span>
          </FormItem>
          <FormItem label="Confirm New Password *">
            <Input
              placeholder="Confirm New Password"
              v-model="data.password_confirmation"
              type="password"
            />
            <span class="text-danger" v-if="errors.password_confirmation">{{
              errors.password_confirmation
            }}</span>
          </FormItem>
        </Form>
      </div>
      <div slot="footer">
        <div></div>
        <div>
          <button class="main-btn main-btn__border" @click="closeModal">
            Cancel
          </button>
          <Button
            class="main-btn main-btn__bg"
            @click="updatePass"
            :disabled="isAdding"
            :loading="isAdding"
            ><i class="fa-solid fa-floppy-disk"></i>
            {{ isAdding ? "Saving.." : "Save" }}</Button
          >
        </div>
      </div>
    </Modal>
  </div>
</template>

<script>
import { mapGetters } from "vuex";
const { io } = require("socket.io-client");
import _ from "lodash";
export default {
  data() {
    return {
      isLoading: false,
      isChatLoading: false,
      isSidebar: false,
      isSearchbar: false,
      isChat: false,
      isChatListBox: false,
      isProfileBox: false,
      isConversationLoading: false,
      // isChatBox: false,
      isConnectionBox: false,
      isConnection: true,
      isRequest: false,
      isNotification: false,
      isNotificationBox: false,
      isPassChangeModal: false,
      isAdding: false,
      isAll: true,
      isRead: false,
      isUnread: false,
      sendRequest: false,
      receivedRequest: false,
      approvedRequest: false,
      sending: false,
      ignored: false,
      loadMoreLoading: false,
      loadMoreNotificationLoading: false,
      noNotificationDataRemaining: false,
      noReadNotificationRemaining: false,
      loadMoreConnectionLoading: false,
      noConnectionDataRemaining: false,
      keyword: "",
      Users: [],
      user_id: -1,
      user_slug: "",
      limit: 6,
      userlimit: 10,
      socket: null,
      isActive: false,
      loadMoreConversationLoading: false,
      loadMoreChatLoading: false,
      noChatRemaining: false,
      noConversationRemaining: false,
      data: {
        msg: "",
        old_password: "",
        password: "",
        password_confirmation: "",
      },
      errmsg: "",
      errors: [],
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
      socketConnected: false,
      isTyping: false,
      selectedChatCompare: "",
      notification: "",
      http: this.$config.IMAGE_URL,
    };
  },
  watch: {
    keyword(after, before) {
      this.getResults();
    },
    "$route.params"(oldValue, newValue) {
      if (oldValue != newValue) {
        this.hideSidebar();

        this.isProfileBox = false;
        if (this.authUser) {
          this.callCount();
          this.callUnseenMsgCount();
        }
      }
    },
  },

  computed: {
    ...mapGetters({
      seenCount: "getSeenCount",
      notificationItem: "getNotificationItem",
      connectionItem: "getAuthUserConnection",
      selectedUserInfo: "getSelectedUserInfo",
      messages: "getMessages",
      isGlobalPostLoading: "getGlobalPostLoading",
      unseenMsgCount: "getUnseenMsgCount",
      isChatBox: "getIsChatBox",
    }),
  },
  methods: {
    showSidebar() {
      this.isSidebar = true;
    },
    hideSidebar() {
      this.isSidebar = false;
    },
    async showChatListBox() {
      this.keyword = "";
      if (this.isChatListBox == false) {
        this.isChatListBox = true;
        this.getConversations();
        if (this.unseenMsgCount > 0) {
          const res = await this.callApi("post", "/api/mark_seen_msg");
          if (res.status == 200) {
            this.$store.dispatch("updateUnseenMsgCount", 0);
          }
        }
      } else {
        this.isChatListBox = false;
      }
      // this.isChatBox = true;
    },

    async showProfileBox() {
      if (this.isProfileBox == false) {
        this.isProfileBox = true;
      } else {
        this.isProfileBox = false;
      }
    },
    hideChatListBox(e) {
      if (this.isChatListBox) {
        let target = e.target;
        var container = this.$refs.chatBoxSearch;
        var source = this.$refs.chatBoxSource;

        if (!source.contains(target) && !container.contains(target)) {
          this.isChatListBox = false;
        }
      }
      // this.isChatListBox = false;
      // this.isProfileBox = false;
    },
    hideProfileBox(e) {
      if (this.isProfileBox) {
        let target = e.target;
        // var container = this.$refs.ProfileBox;
        var source = this.$refs.profileImageSource;

        if (!source.contains(target)) {
          this.isProfileBox = false;
        }
      }
      // this.isChatListBox = false;
      // this.isProfileBox = false;
    },
    hideChatBox() {
      this.$store.commit("setIsChatBox", false);
      this.isActive = false;
      let info = {
        room_id: "",
        selectedUserId: "",
        selectedUserImage: "",
        selectedUserSlug: "",
        selectedUserName: "",
      };
      this.$store.commit("setSelectedUserInfo", info);
      this.selectedChatCompare = [];
    },
    showConnectionBox() {
      if (this.isConnectionBox == false) {
        this.isConnectionBox = true;
        this.getConnection();
      } else {
        this.isConnectionBox = false;
      }
    },
    hideConnectionBox(e) {
      if (this.isConnectionBox) {
        let target = e.target;
        var container1 = this.$refs.connectionBoxBtn1;
        var container2 = this.$refs.connectionBoxBtn2;

        var source = this.$refs.connectionBoxSource;

        if (
          !source.contains(target) &&
          !container1.contains(target) &&
          !container2.contains(target)
        ) {
          this.isConnectionBox = false;
          // this.isRequest = false;
        }
      }
    },

    showSearchbar() {
      this.isSearchbar = true;
      this.$nextTick(() => {
        if (this.$refs["search" + this.keyword]) {
          this.$refs["search" + this.keyword].focus();
        }
      });
    },
    hideSearchbar(e) {
      if (this.isSearchbar) {
        let target = e.target;
        var container = this.$refs.searchBox;
        var source = this.$refs.searchBoxSource;

        if (!source.contains(target) && !container.contains(target)) {
          this.isSearchbar = false;
          this.keyword = "";
        }
      }
    },
    async showNotificationBox() {
      console.log("inside showNotificationBox");
      this.isAll = true;
      this.isUnread = false;
      this.isRead = false;
      this.isProfileBox = false;
      if (this.isNotificationBox == false) {
        this.isNotificationBox = true;
        this.getNotification();
        if (this.seenCount > 0) {
          const res = await this.callApi("post", "/api/mark_as_seen");
          if (res.status == 200) {
            this.$store.dispatch("updateSeenCount", 0);
          }
        }
      } else {
        this.isNotificationBox = false;
      }
    },
    hideNotificationBox(e) {
      if (this.isNotificationBox) {
        let target = e.target;
        var container1 = this.$refs.notificationBoxBtn1;
        var container2 = this.$refs.notificationBoxBtn2;

        var source = this.$refs.notificationBoxSource;

        if (
          !source.contains(target) &&
          !container1.contains(target) &&
          !container2.contains(target)
        ) {
          this.isNotificationBox = false;
        }
      }
    },
    cancelSearchBar() {
      this.isSearchbar = false;
      this.keyword = "";
    },
    clearSearchBar() {
      this.keyword = "";
    },
    getSearchedUser(user) {
      //     const res = await this.callApi(
      //     "get",
      //     `/api/get_profile_info/${this.user_id}`
      // );
      this.user_slug = user.slug;
      this.hideSearchbar(user);
      this.$router.push(`/profile/${this.user_slug}/overview`);
      // this.keyword = "";
    },
    async getResults() {
      const res = await this.callApi(
        "get",
        `/api/search?keyword=${this.keyword}&limit=${this.userlimit}`
      );
      if (res.status == 200) {
        this.Users = res.data;
      } else {
        this.swr();
      }
    },
    async loadMoreUser(more) {
      this.userlimit = this.userlimit + more;
      this.loadMoreLoading = true;
      const res = await this.callApi(
        "get",
        `/api/search?keyword=${this.keyword}&limit=${this.userlimit}`
      );
      if (res.status == 200) {
        this.Users = res.data;

        // for (let i in res.data.data) {
        //   console.log("pushing data");
        //   let d = res.data.data[i];
        //   if (i >= prevLength) {
        //     this.$store.commit("pushConnection", d);
        //   }
        // }
      }
      this.loadMoreLoading = false;
    },

    async markAsRead(index) {
      this.isNotificationBox = false;
      if (this.notificationItem[index].comment_id) {
        console.log(this.notificationItem[index].comment_id);
        this.$store.commit(
          "setCommentId",
          this.notificationItem[index].comment_id
        );
      }
      if (this.notificationItem[index].read_at == null) {
        let id = this.notificationItem[index].id;
        const res = await this.callApi("get", `/api/mark_as_read/${id}`);
      }
    },
    async getDepartments() {
      const res = await this.callApi("get", "/api/get_departments");
      if (res.status == 200) {
        this.$store.commit("updateDepartment", res.data.data);
      } else {
        this.swr();
      }
    },

    async getConnection() {
      this.isConnection = true;
      this.isRequest = false;
      this.isLoading = true;
      const connection = await this.callApi(
        "get",
        `/api/get_auth_user_connection?limit=${this.limit}`
      );

      if (connection.status == 200) {
        this.$store.commit("updateAuthUserConnection", connection.data.data);
      }
      this.isLoading = false;
    },
    async loadMoreConnection(more) {
      console.log("Load more is calling! length", this.connectionItem.length);
      if (this.noConnectionDataRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreConnectionLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_auth_user_connection?limit=${this.limit}`
      );
      if (res.status == 200) {
        let prevLength = this.connectionItem.length;
        if (this.connectionItem.length == res.data.data.length) {
          this.noConnectionDataRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.$store.commit("pushAuthUserConnection", d);
          }
        }
      }
      this.loadMoreConnectionLoading = false;
      console.log("Load more is finished! length", this.connectionItem.length);
    },
    async getRequest() {
      this.isConnection = false;
      this.isRequest = true;
      this.isLoading = true;
      const connection = await this.callApi(
        "get",
        `/api/get_connection_request?limit=${this.limit}`
      );

      if (connection.status == 200) {
        this.$store.commit("updateAuthUserConnection", connection.data.data);
      }
      this.isLoading = false;
    },
    async getNotification() {
      this.isAll = true;
      this.isRead = false;
      this.isUnread = false;
      this.isRequest = false;
      this.isLoading = true;
      const notification = await this.callApi(
        "get",
        `/api/get_notification?limit=${this.limit}`
      );
      // const notification = await this.callApi("get", `/api/get_notification`);

      if (notification.status == 200) {
        console.log(notification.data.data);
        this.$store.dispatch("updateSeenCount", notification.data.count);
        this.$store.dispatch("updateNotification", notification.data.data);
      }
      this.isLoading = false;
    },
    async loadMoreNotification(more) {
      console.log("Load more is calling! length", this.notificationItem.length);

      if (this.noNotificationDataRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreNotificationLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_notification?limit=${this.limit}`
      );

      if (res.status == 200) {
        let prevLength = this.notificationItem.length;
        if (this.notificationItem.length == res.data.data.length) {
          this.noNotificationDataRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.notificationItem.push(d);
            // this.$store.commit("pushAllGlobalPost", d);
          }
        }
      }
      this.loadMoreNotificationLoading = false;
      console.log(
        "Load more is finished! length",
        this.notificationItem.length
      );
    },
    async callCount() {
      const res = await this.callApi(
        "get",
        `/api/get_notification_count?count=${this.seenCount}`
      );

      if (res.status == 200) {
        this.$store.dispatch("updateSeenCount", res.data.data);
      }
    },
    async callUnseenMsgCount() {
      const res = await this.callApi("get", `/api/get_unseenmsg_count`);
      if (res.status == 200) {
        this.$store.dispatch("updateUnseenMsgCount", res.data.count);
      }
    },
    async getReadNotification() {
      this.isAll = false;
      this.isRead = true;
      this.isUnread = false;
      this.isRequest = false;
      this.isLoading = true;

      const notification = await this.callApi(
        "get",
        `/api/get_read_notification?limit=${this.limit}`
      );

      if (notification.status == 200) {
        console.log(notification.data.data);
        this.$store.dispatch("updateNotification", notification.data.data);
      }
      this.isLoading = false;
    },
    async loadMoreReadNotification(more) {
      console.log("Load more is calling! length", this.notificationItem.length);

      if (this.noReadNotificationRemaining) return;

      this.limit = this.limit + more;
      this.loadMoreNotificationLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_read_notification?limit=${this.limit}`
      );

      if (res.status == 200) {
        let prevLength = this.notificationItem.length;
        if (this.notificationItem.length == res.data.data.length) {
          this.noReadNotificationRemaining = true;
        }
        for (let i in res.data.data) {
          console.log("pushing data");
          let d = res.data.data[i];
          if (i >= prevLength) {
            this.notificationItem.push(d);
            // this.$store.commit("pushAllGlobalPost", d);
          }
        }
      }
      this.loadMoreNotificationLoading = false;
      console.log(
        "Load more is finished! length",
        this.notificationItem.length
      );
    },
    async getUnreadNotification() {
      this.isAll = false;
      this.isRead = false;
      this.isUnread = true;
      this.isRequest = false;
      this.isLoading = true;
      const notification = await this.callApi(
        "get",
        `/api/get_unread_notificationlimit=${this.limit}`
      );
      if (notification.status == 200) {
        console.log(notification.data.data);
        this.$store.dispatch("updateNotification", notification.data.data);
      }
      this.isLoading = false;
    },
    async getConversations() {
      this.isConversationLoading = true;
      const res = await this.callApi(
        "get",
        `/api/get_conversation?limit=${this.limit}`
      );
      if (res.status == 200) {
        this.conversations = _.orderBy(
          res.data.data,
          "latest_message.created_at",
          "desc"
        );
      }
      this.isConversationLoading = false;
    },
    sortArrays(arrays) {
      return _.orderBy(arrays, "latest_message.created_at", "desc");
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
      this.$store.commit("setIsChatBox", true);
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
      this.isChatLoading = true;
      const response = await this.callApi(
        "get",
        `/api/get_chat?limit=${3}&roomId=${roomId}`
      );
      if (response.status == 200) {
        this.$store.commit("setMessages", response.data.data);
        this.socket.emit("join chat", roomId);
      } else this.swr();
      this.isChatLoading = false;
      this.isChatListBox = false;
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
        // this.isTyping = true;
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
      if (this.data.msg.trim() == "") return;

      if (this.data.msg) {
        this.socket.emit("stop typing", this.selectedUserInfo.room_id);
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
    async callUnseenMsgNotif(newMessageRecieved) {
      // const room_id = this.notification.room_id;
      console.log("newMessageRecieved" + newMessageRecieved.room_id);
      const obj = {
        room_id: newMessageRecieved.room_id,
        to_id: newMessageRecieved.to_id,
        from_id: newMessageRecieved.from_id,
      };
      const res = await this.callApi("post", `/api/add_unseenmsg_count`, obj);
      if (res.status == 200) {
        this.conversations = res.data.data;
      }
      if (this.authUser) {
        this.callUnseenMsgCount();
      }
      // // if (res.status == 200) {
      // this.$store.dispatch("updateUnseenMsgCount", res.data.count);
      // // }
    },
    async updatePass() {
      // if (this.data.old_password.trim() == "")
      //   return this.e("Old Password is required");
      // if (this.data.password.trim() == "")
      //   return this.e("New Password is required");
      // if (this.data.password_confirmation.trim() == "")
      //   return this.e("Confirm New Password is required");
      // if (this.data.password.trim() !== this.data.password_confirmation.trim())
      //   return this.e("Password Mismatch!!");
      this.errors = [];
      this.isAdding = true;
      const res = await this.callApi("post", "/api/update_pass", this.data);
      if (res.status == 201) {
        this.s(res.data.msg);
        this.closeModal();
      } else {
        if (res.status == 422) {
          this.errmsg = "";
          if (res.data.old_password) {
            this.errors.old_password = res.data.old_password[0];
            // this.e(res.data.email[0]);
          }
          if (res.data.password) {
            this.errors.password = res.data.password[0];
          }
          if (res.data.password_confirmation) {
            this.errors.password_confirmation =
              res.data.password_confirmation[0];
          }
          // for (let i in res.data.errors) {
          //   this.errors = res.data.errors;
          //   console.log(this.errors);
          //   // this.e(res.data.errors[i][0]);
          // }
        } else if (res.status == 401) {
          this.errmsg = res.data.msg;
        } else {
          this.swr();
        }
      }
      this.isAdding = false;
    },
    changePass() {
      this.$store.commit("setGlobalPostLoading", false);
      this.errors = [];
      this.errmsg = "";
      this.data.old_password = "";
      this.data.password = "";
      this.data.password_confirmation = "";
      this.isPassChangeModal = true;
    },
    closeModal() {
      this.errors = [];
      this.errmsg = "";
      this.data.old_password = "";
      this.data.password = "";
      this.data.password_confirmation = "";
      this.isPassChangeModal = false;
    },
    // async getRequestNotification() {
    //   this.isAll = false;
    //   this.isRead = false;
    //   this.isUnread = false;
    //   this.isRequest = true;
    //   this.isLoading = true;
    //   const notification = await this.callApi(
    //     "get",
    //     "/api/get_request_notification"
    //   );
    //   if (notification.status == 200) {
    //     console.log(notification.data.data);
    //     this.$store.dispatch("updateNotification", notification.data.data);
    //   }
    //   this.isLoading = false;
    // },
    async logout() {
      try {
        const res = await this.callApi("get", "/api/logout");
        if (res.status == 200) {
          // this.$router.push(`/`);
          this.hideChatBox();
          this.$store.commit("setAuthInfo", false);
          this.setCookie("token", null);
          this.$router.push(`/`);

          this.s("You Are Logged Out");
        } else {
          this.swr();
        }
      } catch (error) {
        console.log(error);
      }
    },
  },

  mounted() {
    document.addEventListener("click", this.hideSearchbar);
    document.addEventListener("click", this.hideChatListBox);
    document.addEventListener("click", this.hideProfileBox);
    document.addEventListener("click", this.hideNotificationBox);
    document.addEventListener("click", this.hideConnectionBox);

    this.socket = io(this.$config.SOCKET_URL, {
      methods: ["GET", "POST"],
      transports: ["websocket"],
      credentials: true,
    });
    this.socket.on("get_notification", (data) => {
      console.log(data);
      if (data.id == this.authUser.id) this.callCount();
    });
    // this.socket.on("chatNotificationToClient", (data) => {
    //   console.log(data);
    //   if (data.to_id == this.authUser.id) this.callUnseenMsgCount();
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
          this.callUnseenMsgNotif(newMessageRecieved);
        }
      } else {
        console.log("inside else");
        this.messages.push(newMessageRecieved);
      }
    });
    if (this.authUser) {
      const el = this.$refs.scrollConv;
      el.onscroll = () => {
        this.bottomOfWindow =
          window.pageYOffset + window.innerHeight >
          document.body.scrollHeight - 200;
        if (this.bottomOfWindow) {
          if (!this.loadMoreConversationLoading) {
            this.loadMoreConversations(4);
          }
        }
      };

      // const el2 = this.$refs.scrollNotification;
      // el2.onscroll = () => {
      //   this.bottomOfWindow =
      //     window.pageYOffset + window.innerHeight >
      //     document.body.scrollHeight - 200;
      //   if (this.bottomOfWindow) {
      //     if (!this.loadMoreConversationLoading) {
      //       this.loadMoreNotification(4);
      //     }
      //   }
      // };

      // const el3 = this.$refs.scrollConn;
      // el3.onscroll = () => {
      //   this.bottomOfWindow =
      //     window.pageYOffset + window.innerHeight >
      //     document.body.scrollHeight - 200;
      //   if (this.bottomOfWindow) {
      //     if (!this.loadMoreConversationLoading) {
      //       this.loadMoreConnection(4);
      //     }
      //   }
      // };
      // if (this.isActive == true) {
      const el1 = this.$refs.scrollToMe;
      // }
      this.scrollToEnd();
      this.callCount();
      this.callUnseenMsgCount();
      // this.getConnection();
      // const scrollNotification = this.$refs.scrollNotification;
      // scrollNotification.onscroll = () => {
      //   this.bottomOfWindow =
      //     window.pageYOffset + window.innerHeight >
      //     document.body.scrollHeight - 100;

      //   if (this.bottomOfWindow) {
      //     if (!this.loadMoreNotificationLoading) {
      //       this.loadMoreNotification(5);
      //     }
      //   }
      // };
    }
  },
  updated() {
    // this.$nextTick(() => this.scrollToEnd());
    this.scrollToEnd();
  },
  beforeDestroy() {
    document.removeEventListener("click", this.hideSearchbar);
    document.removeEventListener("click", this.hideChatListBox);
    document.removeEventListener("click", this.hideProfileBox);
    document.removeEventListener("click", this.hideNotificationBox);
    document.removeEventListener("click", this.hideConnectionBox);
  },
  // async asyncData({ app, store, redirect, params }) {
  //   try {
  //     let [res] = await Promise.all([app.$axios.get(`/api/get_departments`)]);
  //     return {
  //       departments: res.data.data,
  //     };
  //   } catch (error) {
  //     console.log("error from asyncData server");
  //     console.log(error);
  //     //   return redirect("/");
  //   }
  // },
  async created() {
    if (this.authUser) {
      this.isProfileBox = false;

      this.callCount();
      this.callUnseenMsgCount();
    }
  },
};
</script>
