<template>
  <div class="connection--item mt-40">
    <h5 class="post-title">
      Reorder Banners<a
        class="main-btn float-end"
        @click="$router.push('/admin/banners')"
        >Cancel</a
      >
    </h5>

    <section class="container">
      <div class="teacher-section">
        <div class="teacher-section--table">
          <div v-if="banners.length == 0" class="loader-lg">
            <i class="ivu-load-loop ivu-icon ivu-icon-ios-loading"></i>
          </div>
          <table class="table table-bordered" v-else>
            <thead>
              <tr class="tr">
                <th scope="col">Order No.</th>
                <th scope="col">Image</th>
              </tr>
            </thead>
            <tbody>
              <draggable
                :list="banners"
                @change="log"
                :disabled="!enabled"
                class="list-group"
                ghost-class="ghost"
                @start="dragging = true"
                @end="dragging = false"
              >
                <tr class="li active" v-for="(data, index) in banners">
                  <!-- {{ page }} -->
                  <td>
                    <span v-if="page > 1">{{
                      index + 1 + (page - 1) * 20
                    }}</span>
                    <span v-else>{{ index + 1 }}</span>
                  </td>
                  <td>
                    <img :src="`${http + data.image}`" />
                  </td>
                </tr>
              </draggable>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</template>
<script>
import draggable from "vuedraggable";
export default {
  components: {
    name: "simple",
    display: "Simple",
    order: 0,
    draggable,
  },
  data() {
    return {
      enabled: true,
      isDataLoading: false,
      banners: [],
      new_list: [],
      newData: [],
      page: 1,
      firstItem: 0,
      lastItem: 1,
      disabled: 0,
      http: "http://127.0.0.1:8000/images/",
    };
  },
  methods: {
    newList() {
      this.new_list = [];
      this.banners.forEach((data, i) => {
        this.new_list.push(data.order_no);
      });
      return (this.disabled = 0);
    },
    log: function (e) {
      this.newData = [];
      this.banners.forEach((data, i) => {
        let obj = {
          id: data.id,
          order_no: this.new_list[i],
        };
        this.newData.push(obj);
        // this.newList[i].order=data.id
      });
      this.resetProduct();
    },
    async getBanners() {
      this.disabled = 1;
      //   this.isDataLoading = true;
      let url = `/api/main_banner_all?page=${this.page}&lastItem=${this.firstItem}`;
      const res = await this.callApi("get", url);
      if (res.status == 200) {
        this.banners = res.data;
        this.firstItem = res.data[0].order_no;
        this.lastItem = res.data[this.banners.length - 1].order_no;
        console.log(this.banners.length);
        this.newList();
      } else {
        this.swr();
      }
      //   this.isDataLoading = false;
    },
    async resetProduct() {
      this.disabled = 1;
      const response = await this.callApi(
        "post",
        "/api/reset_banner",
        this.newData
      );
      if (response.status == 200) {
        this.s_msg("Updated Successfully!");
        this.getBanners();
      } else this.swr();
    },
  },

  async created() {
    await this.getBanners();
  },
};
</script>

<style scoped>
.tr {
  list-style-type: none;
  width: 100%;
  display: flex;
  justify-content: space-around;
  align-items: center;
  /* flex:1; */
  gap: 15px;
  text-align: center;
  padding: 5px;
  margin: 8px auto;
}
tr:not(.tr) {
  list-style-type: none;
  width: 100%;
  display: flex;
  border: 1px solid rgb(85, 82, 82);
  justify-content: space-around;
  align-items: center;
  /* flex:1; */
  gap: 15px;
  text-align: center;
  padding: 5px;
  margin: 8px auto;
}

tr:hover:not(.tr) {
  cursor: move;
}
tr td {
  font-size: 16px;
  flex-basis: 180px;
  width: 150px;
  word-break: break-all;
  /* min-width: 150px; */
}
/* tr div{
        margin-right: 0;
        justify-self: flex-end;
    } */
tr td Button {
  margin: 0 3px 2px 0;
}
tr td Button:hover {
  cursor: pointer;
}
.active:active {
  background-color: #021e27 !important;
  color: #fff;
  width: 100%;
  cursor: move;
  border: 1px solid black;
}
</style>
