<template>
  <div>
    <h4 class="menu-item--title">
      {{ abstract.type != "Project" ? "Abstract" : "Description" }}
    </h4>

    <div v-if="isLoading" class="loader">
      <h1 class="mb-1" />
      <h1 class="mb-1" />
      <h1 />
    </div>

    <div v-else>
      <h4 class="sub-title" v-if="abstract.abstract">
        {{ abstract.abstract }}
      </h4>
      <h4 class="sub-title" v-else>
        {{
          abstract.type != "Project"
            ? "The abstract for this research item is not available."
            : "The description for this project is not available."
        }}
      </h4>
    </div>
  </div>
</template>
<script>
export default {
  components: {},
  data() {
    return {
      abstract: [],
      post_slug: "",
      post_id: "",
      isLoading: true,
    };
  },
  methods: {},
  async created() {
    // this.token = window.Laravel.csrfToken;
    this.post_slug = this.$route.params.slug;
    console.log(this.post_slug);
    this.isLoading = true;
    const res = await this.callApi(
      "get",
      `/api/post_abstract/${this.post_slug}`
    );
    if (res.status == 200) {
      this.abstract = res.data.data[0];
    } else {
      this.swr();
    }
    this.isLoading = false;
  },
};
</script>
