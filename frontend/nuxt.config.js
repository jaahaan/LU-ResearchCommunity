export default {
  /*
  ** Nuxt rendering mode
  ** See https://nuxtjs.org/api/configuration-mode
  */
  // mode: 'universal',
  /*
  ** Nuxt target
  ** See https://nuxtjs.org/api/configuration-target
  */
  target: 'server',
  /*
  ** Headers of the page
  ** See https://nuxtjs.org/api/configuration-head
  */
  // Global page headers: https://go.nuxtjs.dev/config-head
  head: {
    title: 'lu-research-community',
    htmlAttrs: {
      lang: 'en'
    },
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: '' },
      { name: 'format-detection', content: 'telephone=no' }
    ],
    link: [
      { rel: 'icon', type: 'image/x-icon', href: '/icon.png' },
      { rel: 'stylesheet', href: "/assets/css/vendor/bootstrap.min.css" },
      { rel: 'stylesheet', href: "/assets/css/vendor/lineicons.css" },
      { rel: 'stylesheet', href: "/assets/css/vendor/line-awesome.min.css"},

      { rel: 'stylesheet', href: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.3.0/css/all.min.css"},

    ],
    script: [{
      src: "https://cdn.jsdelivr.net/npm/emoji-picker-element@^1/index.js",
      type: "module",
      body: true
      },
      // {
      //   src: "https://cdn.socket.io/4.3.2/socket.io.esm.min.js"
      // },
      { src: "https://cdn.socket.io/4.0.1/socket.io.min.js" },
      { src: 'https://js.stripe.com/v3/' },
      {
          src: "https://unpkg.com/peerjs@1.3.1/dist/peerjs.min.js",
          body: true
      },
      {src:"https://unpkg.com/vue-typer/dist/vue-typer.min.js"}
    ]
  },


  // Global CSS: https://go.nuxtjs.dev/config-css
  css: [
    'iview/dist/styles/iview.css',
    'hooper/dist/hooper.css',
    '~static/assets/css/style.scss'
  ],

  // Plugins to run before rendering page: https://go.nuxtjs.dev/config-plugins
  plugins: [
    '@/plugins/serverSidePlugin',

    // { src: '~plugins/serverSidePlugin' ,ssr: 'true'},
    { src: '~plugins/iview' ,mode: 'client'},
  ],

  // Auto import components: https://go.nuxtjs.dev/config-components
  components: true,

  // Modules for dev and build (recommended): https://go.nuxtjs.dev/config-modules
  buildModules: [
  ],

  // Modules: https://go.nuxtjs.dev/config-modules
  modules: [
    '@nuxtjs/axios',

  ],
  
 
/*
  ** Axios module configuration
  ** See https://axios.nuxtjs.org/options
  */
  axios: {
    baseURL: "http://127.0.0.1:8000",
    // baseURL: "https://cameraworldapi.dreamsgallerybd.com",
    credentials: true
  },
  // Build Configuration: https://go.nuxtjs.dev/config-build
  build: {
  },
  server: {
    port: 3000, // default: 3000
    host: 'localhost' // default: localhost
  },
  publicRuntimeConfig: {
    BASE_URL: "http://127.0.0.1:8000",
    IMAGE_URL: "http://127.0.0.1:8000/images/",
    SOCKET_URL: "http://127.0.0.1:5000",
    // SITE_TITLE: process.env.SITE_TITLE,
    // SITE_URL: process.env.SITE_URL,
    // Stripe_Publishable_key: process.env.Stripe_Publishable_key,
    // IS_CAREVAN: process.env.IS_CAREVAN

},
}
