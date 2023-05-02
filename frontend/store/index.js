//import Vuex from 'vuex'
//import axios from 'axios'
export const strict = false
import cookie from 'cookie';

export const state = () => ({
    user : 'no user',
    authUser: false,
    socket: null,
    messages:[],
    conversations:[],
    userResearch:[],
    userProject:[],
    allGlobalResearch:[],
    globalResearchLoading:true,
    allGlobalPost:[],
    allComments:[],
    globalPostLoading:true,
    callNotificationOb:null,
    notification: [],
    connection: [],
    authUserConnection: [],
    departmentInfo: [],
    peopleYouMayKnow:[],
    seenCount:0,
    unseenMsgCount:0,
    token: '',
    passwordReset: { email: "" , otp: ""},
    unauthorizedCredential: { email: "",  password: ""},
    selectedUserInfo: {room_id: "", selectedUserId: "",selectedUserImage:"", selectedUserSlug:"",  selectedUserName: "" },
    commentId: "",
    selectedChat: [],
    chatNotification: [],
    chats:[],
    isChatBox: false,
    isTyping: false,
    themeInfo: [],
})
// common getters
export const getters = {
  getIsLoggedIn (state) {
    return !!state.authUser
  },
  getAuthUser (state) {
    return state.authUser
  },
  getToken (state) {
    return state.token
  },
  unauthorizedCredential(state) {
    return state.unauthorizedCredential;
  },
  passwordReset(state) {
    return state.passwordReset;
  },
  commentId(state) {
    return state.commentId;
  },
  
  getSocket (state) {
    return state.socket
  },
  getDepartment (state) {
    return state.departmentInfo
  },
  
  getSeenCount (state) {
    return state.seenCount
  },
  getUnseenMsgCount (state) {
    return state.unseenMsgCount
  },
  getCallNotificationOb (state) {
    return state.callNotificationOb
  },
  
  getSelectedUserInfo(state) {
    return state.selectedUserInfo;
  },
  
  getConnectionItem (state) {
    return state.connection
  },
  getAuthUserConnection(state) {
    return state.authUserConnection
  },

  getNotificationItem (state) {
    return state.notification
  },
  getPeopleYouMayKnow (state) {
    return state.peopleYouMayKnow
  },
  getSelectedChat (state) {
    return state.selectedChat
  },
  getTheme (state) {
    return state.themeInfo
  },
  getChatNotification (state) {
    return state.chatNotification
  },
  getChats (state) {
    return state.chats
  },
  getMessages (state) {
    return state.messages
  },
  getConversations (state) {
    return state.conversations
  },
  getUserResearch (state) {
    return state.userResearch
  },
  getUserProject (state) {
    return state.userProject
  },
  getAllGlobalResearch (state) {
    return state.allGlobalResearch
  },
  
  getGlobalResearchLoading (state) {
    return state.globalResearchLoading
  },

  getAllGlobalPost (state) {
    return state.allGlobalPost
  },
  getAllComments (state) {
    return state.allComments
  },
  getGlobalPostLoading (state) {
    return state.globalPostLoading
  },
  getIsChatBox (state) {
    return state.isChatBox
  },
  getIsTyping (state) {
    return state.isTyping
  },
}
//mutations for changing data from action
export const mutations = {
  loginUser(state, data) {
    state.authUser = data
  },
  setAuthInfo(state, data) {
    state.authUser = data
  },
  setSocket(state, data) {
    state.socket = data
  },
  setToken(state, data) {
    state.token = data
  },
  setDepartmentInfo (state, data) {
    state.departmentInfo = data
  },
  updateSeenCount(state, data) {
    state.seenCount = data
  },
  updateUnseenMsgCount(state, data) {
    state.unseenMsgCount = data
  },
  removeConnectionItem (state, i) {
    state.connection.splice(i,1)
  },
 
  updateConnection (state, data) {
    state.connection = data
  },

  pushConnection (state, data) {
    state.connection.push(data)
  },

  removeAuthUserConnection (state, i) {
    state.authUserConnection.splice(i,1)
  },
 
  updateAuthUserConnection (state, data) {
    state.authUserConnection = data
  },

  pushAuthUserConnection (state, data) {
    state.authUserConnection.push(data)
  },
  removeNotificationItem (state, i) {
    state.Notification.splice(i,1)
  },
  
  updateNotification (state, data) {
    state.notification = data
  },
  pushNotification (state, data) {
    state.notification.push(data)
  },
  updatePeopleYouMayKnow (state, data) {
    state.peopleYouMayKnow = data
  },
  setSelectedChat (state, data) {
    state.selectedChat = data
  },
  setTheme (state, data) {
    state.themeInfo = data
  },
  setChatNotification (state, data) {
    state.chatNotification = data
  },
  setChats (state, data) {
    state.chats = data
  },
  setCallNotificationOb (state, data) {
    state.callNotificationOb = data
  },
  setUnauthorizedCredential(state, data)  {
    state.unauthorizedCredential = data;
  },

  setSelectedUserInfo(state, data)  {
    state.selectedUserInfo = data;
  },
  setPasswordReset(state, data) {
    state.passwordReset = data;
  },
  setCommentId(state, data) {
    state.commentId = data;
  },
  //user message
  setMessages (state, data) {
    state.messages = data
  },
  
  pushMessages (state, data) {
    state.messages.push(data)
  },

  //user Conversation
  setConversations (state, data) {
    state.conversations = data
  },
  
  pushConversations (state, data) {
    state.conversations.push(data)
  },
  unshiftConversations (state, data) {
    state.conversations.unshift(data)
  },
  //user research
  setUserResearch (state, data) {
    state.userResearch = data
  },
  
  pushUserResearch (state, data) {
    state.userResearch.push(data)
  },
  //user project
  setUserProject (state, data) {
    state.userProject = data
  },

  pushUserProject (state, data) {
    state.userProject.push(data)
  },

  //research
  setAllGlobalResearch (state, data) {
    state.allGlobalResearch = data
  },
  setGlobalResearchLoading (state, data) {
    state.globalResearchLoading = data
  },
  pushAllGlobalResearch (state, data) {
    state.allGlobalResearch.push(data)
  },

  //post
  setAllGlobalPost (state, data) {
    state.allGlobalPost = data
  },
  setGlobalPostLoading (state, data) {
    state.globalPostLoading = data
  },
  pushAllGlobalPost (state, data) {
    state.allGlobalPost.push(data)
  },
  setIsChatBox (state, data) {
    state.isChatBox = data
  },
  setIsTyping (state, data) {
    state.isTyping = data
  },

  setAllComments (state, data) {
    state.allComments = data
  },

  pushAllComments (state, data) {
    state.allComments.unshift(data)
  },
}

// actionns for commiting mutations
export const actions = {
    async nuxtServerInit({ commit, state }, { $axios, req, env })  {
    console.log('I am running as nuxt server init')
    const session = req.headers.cookie ? cookie.parse(req.headers.cookie) : ''
    // console.log("token : ",session)
    $axios.setToken(session.token, 'Bearer');
    try {
      
      const department  = await $axios.get('/api/get_departments')
      console.log(department.data)
      if(department.status == 200){
        commit('setDepartmentInfo', department.data)
      }
      const theme = await $axios.get('/api/get_theme')

      if (theme.status == 200) {
        console.log("inside 200");
        console.log(theme.data);

        commit('setTheme', theme.data);
        console.log(this.themeInfo);
      }
      const res  = await $axios.get('/api/auth_user')
      console.log(res.data)
      commit('setAuthInfo', res.data)
      
      const [notification, peopleYouMayKnow, connection] = await Promise.all([
        this.callApi("get", '/api/get_notification'),
        this.callApi("get", "/api/get_people_you_may_know"),
        this.callApi("get", "/api/get_auth_user_connection"),
      ]);
      if(notification.status == 200 && peopleYouMayKnow.status==200 && connection.status==200){
        console.log(notification.data.data)
        // state.seenCount = notification.data.count
        this.$store.dispatch('updateNotification', notification.data.data)
        this.$store.dispatch('updatePeopleYouMayKnow', peopleYouMayKnow.data.data)
        this.$store.dispatch('updateAuthUserConnection', connection.data.data)
    }
     
    } catch (e) {
        console.log('nuxt server error ')
    }
  },
  

  setToken ({ commit }, data) {
    commit('setToken', data)
  },
  
  updateConnection ({ commit }, data) {
    commit('updateConnection', data)
  },
  updateAuthUserConnection ({ commit }, data) {
    commit('updateAuthUserConnection', data)
  },
  updateNotification ({ commit }, data) {
    commit('updateNotification', data)
  },
  updatePeopleYouMayKnow({commit}, data){
    commit('updatePeopleYouMayKnow', data)
  },
  updateSeenCount ({ commit }, data) {
    commit('updateSeenCount', data)
  },
  updateUnseenMsgCount ({ commit }, data) {
    commit('updateUnseenMsgCount', data)
  },
  setDepartmentInfo ({ commit }, data) {
    commit('setDepartmentInfo', data)
  },
  setTheme ({ commit }, data) {
    commit('setTheme', data)
  },
  setAuthInfo ({ commit }, data) { 
    commit('setAuthInfo', data)
  },
  setSocket ({ commit }, data) { 
    commit('setSocket', data)
  },
}
