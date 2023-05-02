<template>
  <div>
    <!--*************** Top Banner ***************-->
    <section class="hero-section">
      <hooper
        class="no-margin"
        :settings="hooperSettings"
        :wheelControl="false"
      >
        <slide
          class="item hero-section__bg"
          v-for="(data, index) in dataBanner"
          :key="index"
          v-if="data.type == 'slider'"
          :style="{ backgroundImage: `url(${http + data.image})` }"
        >
        </slide>

        <!-- <slide
          class="item hero-section__bg"
          :style="{ backgroundImage: `url('/assets/images/view1.jpeg')` }"
        >
        </slide>
        <slide
          class="item hero-section__bg"
          :style="{ backgroundImage: `url('/assets/images/view2.jpeg')` }"
        >
        </slide>
        <slide
          class="item hero-section__bg"
          :style="{ backgroundImage: `url('/assets/images/view3.jpeg')` }"
        >
        </slide>
        <slide
          class="item hero-section__bg"
          :style="{ backgroundImage: `url('/assets/images/view4.jpeg')` }"
        >
        </slide>
        <slide
          class="item hero-section__bg"
          :style="{ backgroundImage: `url('/assets/images/view5.jpg')` }"
        >
        </slide>
        <slide
          class="item hero-section__bg"
          :style="{ backgroundImage: `url('/assets/images/view6.jpeg')` }"
        >
        </slide>
        <slide
          class="item hero-section__bg"
          :style="{ backgroundImage: `url('/assets/images/view7.jpeg')` }"
        >
        </slide> -->
        <HooperPagination slot="hooper-addons"></HooperPagination>
      </hooper>
      <div class="right">
        <div class="right-details">
          <div class="right-details--area">
            <h4 class="right-details--area---subtitle">WELCOME TO</h4>
            <h4 class="right-details--area---title">
              <span>LU REASEARCH COMMUNITY</span>
            </h4>
            <h4 class="right-details--area---subtitle">
              Find our

              <vue-typer caret-animation="expand" :text="typer"> </vue-typer>
            </h4>
          </div>
        </div>
      </div>
    </section>

    <!--*************** Random ***************-->
    <div class="container-fluid">
      <div class="quote-section row">
        <div class="col-12 col-md-6">
          <h1 class="col-lg-10 _card">
            Science is a way of thinking much more than it is a body of
            knowledge.
          </h1>
        </div>
        <div class="col-12 col-md-6 image">
          <img
            :src="'/assets/images/pixel.png'"
            alt="img"
            class="img-fluid slider h-70"
          />
        </div>
      </div>
    </div>

    <!--*************** About ***************-->
    <div class="container-fluid">
      <div class="quote-section row" id="about">
        <div class="col-12 col-md-6 image">
          <img
            :src="'/assets/images/stat.png'"
            alt="img"
            class="img-fluid slider h-50"
          />
        </div>
        <div class="col-12 col-md-6">
          <h1 class="col-lg-10 _card">
            Our mission is to help the students gather knowledge about research
            field and find the research works of our honourable teachers that
            can guide them to find out their own research interest.
          </h1>
        </div>
      </div>
    </div>

    <!--*************** Random ***************-->
    <div class="container-fluid">
      <div class="quote-section row">
        <div class="col-12 col-md-6">
          <h1 class="col-lg-10 _card">
            Connect with our research community to share your thoughts,
            collaborate with your teachers, colleagues and friends.
          </h1>
        </div>
        <div class="col-12 col-md-6 image">
          <img
            :src="'/assets/images/remote.png'"
            alt="img"
            class="img-fluid slider w-50"
          />
        </div>
      </div>
    </div>
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

export default {
  name: "index",
  middleware: "guest",

  components: {
    Hooper,
    Slide,
    HooperProgress,
    HooperPagination,
    HooperNavigation,
  },

  data() {
    return {
      dataBanner: [],
      typer: [
        "Research",
        "Publications",
        "Articles",
        "Preprint",
        "Projects",
        "Presentation",
        "Poster",
      ],

      isDataLoading: true,
      hooperSettings: {
        infiniteScroll: true,
        centerMode: true,
        autoPlay: true,
        playSpeed: 2000,
        breakpoints: {
          1200: {
            itemsToShow: 1,
          },

          995: {
            itemsToShow: 1,
          },
          0: {
            itemsToShow: 1,
          },
        },
      },
      http: this.$config.IMAGE_URL,
    };
  },

  methods: {},
  async asyncData({ app, store, redirect, params }) {
    try {
      let [res] = await Promise.all([app.$axios.get(`/api/landing_banners`)]);
      return {
        dataBanner: res.data.data,
      };
    } catch (error) {
      console.log("error from asyncData server");
      console.log(error);
      //   return redirect("/");
    }
  },

  async created() {
    console.log("index page");
    // if (this.authUser) {
    //   window.location = "/home";
    // } else {
    // const response = await this.callApi("get", "/api/banners");
    // if (response.status == 200) {
    //   this.dataBanner = response.data.data;
    //   console.log("index page");
    // } else this.e("Oops!", "Something went wrong, please try again!");
    // this.isDataLoading = false;
  },
};
</script>
