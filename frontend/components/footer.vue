<template>
  <div>
    <footer>
      <div class="container">
        <div class="footer-info">
          <div class="footer-info__item">
            <h3>Contact Us</h3>
            <ul class="footer-info__item--icon">
              <li>
                <a
                  class="ga-events"
                  data-eventcategory="Phone track footer"
                  data-eventaction="Click to call"
                  data-eventlabel="01759486292"
                  href="tel:01759486292"
                  ><i class="lni lni-phone"></i
                ></a>
              </li>
              <li>
                <a
                  class="ga-events"
                  data-eventcategory="Mail from footer"
                  data-eventaction="Click to action"
                  data-eventlabel="info@lurc.ac.bd"
                  href="mailto:info@lurc.ac.bd"
                  ><i class="lni lni-envelope"></i
                ></a>
              </li>
              <li>
                <a href="https://www.lus.ac.bd" target="_blank"
                  ><i class="lni lni-world"></i
                ></a>
              </li>

              <li>
                <a
                  href="https://www.facebook.com/leadinguniversity2001/"
                  target="_blank"
                >
                  <i class="lni lni-facebook-filled"></i
                ></a>
              </li>
              <li>
                <a
                  href="https://www.youtube.com/channel/UC3UkVH9fhmQQCKSzQAMRwWA"
                  target="_blank"
                >
                  <i class="lni lni-youtube"></i
                ></a>
              </li>
            </ul>
          </div>
          <div class="footer-info__item">
            <h3>Leading University</h3>
            <p>Ragibnagar, South Surma, Sylhet-3112</p>
          </div>
          <div class="footer-info__item">
            <h3>Privacy Policy</h3>
            <p>Terms & Conditions</p>
          </div>
        </div>
      </div>
      <div class="container">
        <div class="footer-copyright">
          <p>
            copyright © {{ new Date().getFullYear() }} Team LURC all rights
            reserved
          </p>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
export default {
  name: "Footer",

  data() {
    return {};
  },
  components: {},
  methods: {},
  async created() {},
};
</script>
