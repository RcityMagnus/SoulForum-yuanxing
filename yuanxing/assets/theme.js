(function () {
  const NAV_GROUPS = [
    {
      name: "工作台",
      entryModule: "工作台",
      entryPage: "01-后台数据总览.html",
      modules: ["工作台"],
    },
    {
      name: "内容治理",
      entryModule: "内容管理",
      entryPage: "01-主题管理列表.html",
      modules: ["内容管理", "审核与举报"],
    },
    {
      name: "会员治理",
      entryModule: "会员管理",
      entryPage: "01-会员列表.html",
      modules: ["会员管理"],
    },
    {
      name: "社区结构",
      entryModule: "社区结构",
      entryPage: "01-分区与板块管理.html",
      modules: ["社区结构"],
    },
    {
      name: "权限与安全",
      entryModule: "权限与安全",
      entryPage: "01-用户组管理.html",
      modules: ["权限与安全"],
    },
    {
      name: "注册与封禁",
      entryModule: "注册与登录",
      entryPage: "01-后台注册新会员.html",
      modules: ["注册与登录", "风控与处罚"],
    },
    {
      name: "运营与触达",
      entryModule: "通知与私信",
      entryPage: "01-站内公告列表.html",
      modules: ["通知与私信"],
    },
    {
      name: "平台支撑",
      entryModule: "搜索与SEO",
      entryPage: "01-搜索权重设置.html",
      modules: ["搜索与SEO", "附件与媒体", "系统设置"],
    },
    {
      name: "扩展与审计",
      entryModule: "日志与审计",
      entryPage: "01-管理员操作日志.html",
      modules: ["数据报表", "日志与审计", "扩展中心"],
    },
  ];

  const MODULE_TO_GROUP = NAV_GROUPS.reduce((map, group) => {
    group.modules.forEach((moduleName) => {
      map[moduleName] = group.name;
    });
    return map;
  }, {});

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function pathInfo() {
    const parts = decodeURIComponent(location.pathname).split("/").filter(Boolean);
    const candidates = ['yuanxing', '原型界面', '_极简原型页面'];
    const rootIndex = Math.max(...candidates.map((name) => parts.lastIndexOf(name))); 
    const module = rootIndex >= 0 ? parts[rootIndex + 1] || "" : "";
    const file = rootIndex >= 0 ? parts[rootIndex + 2] || "index.html" : "index.html";
    return { module, file };
  }

  function currentGroupName(currentModule) {
    return MODULE_TO_GROUP[currentModule] || currentModule || "";
  }

  function buildSidebar(currentModule, currentTitle, rootPrefix) {
    const sidebar = el("aside", "sd-sidebar");
    const groupName = currentGroupName(currentModule);

    const brand = el("div", "sd-brand");
    brand.append(el("div", "sd-brand-mark", "SD"));
    const brandMeta = el("div");
    brandMeta.append(el("h2", "", "论坛后台"));
    brandMeta.append(el("p", "", "论坛管理员后台原型"));
    brand.append(brandMeta);
    sidebar.append(brand);

    const card1 = el("div", "sd-sidebar-card");
    card1.append(el("strong", "", groupName || "总览"));
    card1.append(el("p", "sd-sidebar-note", currentTitle || "页面导航与原型浏览"));
    card1.append(el("span", "sd-chip", groupName ? "当前模块" : "总目录"));
    sidebar.append(card1);

    const navGroup = el("div", "sd-nav-group");
    navGroup.append(el("div", "sd-nav-title", "主要模块"));
    NAV_GROUPS.forEach((group) => {
      const link = el(
        "a",
        "sd-nav-link" + (group.name === groupName ? " is-active" : "")
      );
      link.href = `${rootPrefix}${group.entryModule}/${group.entryPage}`;
      link.textContent = group.name;
      navGroup.append(link);
    });
    sidebar.append(navGroup);

    const card2 = el("div", "sd-sidebar-card");
    card2.append(el("strong", "", "当前说明"));
    card2.append(
      el(
        "p",
        "sd-sidebar-note",
        "页面保留后台骨架、信息结构与关键交互，视觉风格统一参考样式图。"
      )
    );
    sidebar.append(card2);

    return sidebar;
  }

  function buildTopbar(currentModule) {
    const topbar = el("div", "sd-topbar");
    const search = el("div", "sd-search");
    const input = document.createElement("input");
    input.type = "text";
    input.placeholder = "搜索页面、字段、按钮";
    search.append(input);
    topbar.append(search);

    const actions = el("div", "sd-top-actions");
    actions.append(el("span", "sd-chip", currentModule || "总览"));

    const preview = el("button", "ghost", "预览模式");
    preview.type = "button";
    actions.append(preview);

    const source = el("button", "", "原型文件");
    source.type = "button";
    actions.append(source);

    actions.append(el("div", "sd-avatar", "A"));
    topbar.append(actions);
    return topbar;
  }

  function collectNodes(nodes) {
    return Array.from(nodes).filter((node) => {
      if (node.nodeType !== 1) return false;
      if (node.tagName === "SCRIPT") return false;
      return true;
    });
  }

  function normalizeButtons(container) {
    container.querySelectorAll("button").forEach((button) => {
      if (!button.type) button.type = "button";
    });
  }

  function wrapCard(node, title) {
    const card = el("section", "sd-card");
    if (title) card.append(el("h2", "", title));
    card.append(node);
    return card;
  }

  function enhanceForm(form) {
    const card = el("section", "sd-card");
    const fieldsets = Array.from(form.querySelectorAll(":scope > fieldset"));
    const loose = Array.from(form.children).filter(
      (child) => child.tagName !== "FIELDSET"
    );

    if (fieldsets.length) {
      const stack = el("div", "sd-section-stack");
      fieldsets.forEach((fs) => {
        const box = el("div", "sd-card compact");
        const legend = fs.querySelector("legend");
        if (legend) {
          box.append(el("h3", "", legend.textContent.trim()));
          legend.remove();
        }

        const grid = el("div", "sd-form-grid");
        Array.from(fs.children).forEach((child) => {
          if (child.tagName === "P") {
            const text = child.textContent || "";
            if (child.querySelector("textarea") || text.length > 42) {
              child.classList.add("full");
            }
          }
          grid.append(child);
        });
        box.append(grid);
        stack.append(box);
      });
      card.append(stack);
    } else {
      const grid = el("div", "sd-form-grid");
      loose.forEach((child) => {
        if (
          child.tagName === "P" &&
          (child.querySelector("textarea") || (child.textContent || "").length > 42)
        ) {
          child.classList.add("full");
        }
        grid.append(child);
      });
      card.append(grid);
    }

    return card;
  }

  function enhanceSection(section) {
    const card = el("section", "sd-card");
    const firstTitle = section.querySelector(":scope > h2, :scope > h3");
    if (firstTitle) {
      card.append(el("h2", "", firstTitle.textContent.trim()));
      firstTitle.remove();
    }
    card.append(section);
    return card;
  }

  function buildIndexPage() {
    const original = collectNodes(document.body.childNodes);
    const h1 = original.find((n) => n.tagName === "H1");
    const intro = original.find((n) => n.tagName === "P");
    const groups = [];

    for (let i = 0; i < original.length; i++) {
      if (original[i].tagName === "H2" && original[i + 1] && original[i + 1].tagName === "UL") {
        groups.push({
          title: original[i].textContent.trim(),
          list: original[i + 1],
        });
      }
    }

    document.body.innerHTML = "";
    const app = el("div", "sd-app");
    app.append(buildSidebar("", h1 ? h1.textContent.trim() : "总目录", "./"));

    const main = el("main", "sd-main");
    main.append(buildTopbar("总目录"));

    const hero = el("section", "sd-hero");
    hero.append(el("h1", "", h1 ? h1.textContent.trim() : "论坛管理员后台原型"));
    hero.append(
      el("p", "", intro ? intro.textContent.trim() : "按模块浏览所有原型页面。")
    );
    main.append(hero);

    const grid = el("div", "sd-index-grid");
    groups.forEach(({ title, list }) => {
      const card = el("section", "sd-card sd-index-group");
      card.dataset.module = title;
      card.id = title;
      card.append(el("h2", "", title));
      card.append(list);
      grid.append(card);
    });

    main.append(grid);
    app.append(main);
    document.body.append(app);
    bindIndexNavigation();
  }

  function bindIndexNavigation() {
    const cards = Array.from(document.querySelectorAll(".sd-index-group"));
    const links = Array.from(document.querySelectorAll(".sd-sidebar .sd-nav-link"));
    if (!cards.length || !links.length) return;

    const heroTitle = document.querySelector(".sd-hero h1");
    const heroText = document.querySelector(".sd-hero p");
    const sidebarTitle = document.querySelector(".sd-sidebar-card strong");
    const sidebarNote = document.querySelector(".sd-sidebar-card .sd-sidebar-note");
    const sidebarChip = document.querySelector(".sd-sidebar-card .sd-chip");

    function render(moduleName) {
      const activeName = moduleName && cards.some((card) => card.dataset.module === moduleName)
        ? moduleName
        : "";

      cards.forEach((card) => {
        const match = !activeName || card.dataset.module === activeName;
        card.style.display = match ? "" : "none";
      });

      links.forEach((link) => {
        const match = decodeURIComponent(link.hash.replace(/^#/, "")) === activeName;
        link.classList.toggle("is-active", match);
      });

      if (activeName) {
        if (heroTitle) heroTitle.textContent = activeName;
        if (heroText) heroText.textContent = `当前展示“${activeName}”模块下的原型页面。`;
        if (sidebarTitle) sidebarTitle.textContent = activeName;
        if (sidebarNote) sidebarNote.textContent = "点击左侧其他模块可切换展示对应页面目录。";
        if (sidebarChip) sidebarChip.textContent = "当前模块";
      } else {
        if (heroTitle) heroTitle.textContent = "论坛管理员后台原型界面";
        if (heroText) heroText.textContent = "基于《论坛管理员后台信息架构IA》和《论坛管理员后台原型页面总目录》生成，统一采用后台工作台风格。";
        if (sidebarTitle) sidebarTitle.textContent = "总览";
        if (sidebarNote) sidebarNote.textContent = "页面导航与原型浏览";
        if (sidebarChip) sidebarChip.textContent = "总目录";
      }
    }

    function syncFromHash() {
      const moduleName = decodeURIComponent(location.hash.replace(/^#/, ""));
      render(moduleName);
    }

    links.forEach((link) => {
      link.addEventListener("click", (event) => {
        const target = decodeURIComponent(link.hash.replace(/^#/, ""));
        if (!target) return;
        event.preventDefault();
        history.replaceState(null, "", `#${encodeURIComponent(target)}`);
        render(target);
      });
    });

    window.addEventListener("hashchange", syncFromHash);
    syncFromHash();
  }

  function buildDetailPage() {
    const { module } = pathInfo();
    const rootPrefix = "../";
    const groupName = currentGroupName(module);
    const original = collectNodes(document.body.childNodes);
    const back = original.find((n) => n.tagName === "P" && n.querySelector("a"));
    const titleNode = original.find((n) => n.tagName === "H1");
    const breadcrumb = original.find(
      (n) => n.tagName === "P" && !n.querySelector("a") && n !== back
    );
    const nav = original.find((n) => n.tagName === "NAV");
    const contentNodes = original.filter(
      (n) => ![back, titleNode, breadcrumb, nav].includes(n)
    );

    document.body.innerHTML = "";
    const app = el("div", "sd-app");
    app.append(buildSidebar(module, titleNode ? titleNode.textContent.trim() : "", rootPrefix));

    const main = el("main", "sd-main");
    main.append(buildTopbar(groupName || module || "页面"));

    const hero = el("section", "sd-hero");
    hero.append(el("h1", "", titleNode ? titleNode.textContent.trim() : "页面"));
    hero.append(
      el("p", "", breadcrumb ? breadcrumb.textContent.trim() : "论坛后台原型页面")
    );
    main.append(hero);

    if (nav) {
      const tabs = el("div", "sd-tabs");
      Array.from(nav.querySelectorAll("a")).forEach((link) => {
        const a = el("a", "sd-tab");
        a.href = link.getAttribute("href") || "#";
        a.textContent = link.textContent.trim();
        if (titleNode && link.textContent.trim() === titleNode.textContent.trim()) {
          a.classList.add("is-active");
        }
        tabs.append(a);
      });
      main.append(tabs);
    }

    const grid = el("div", "sd-grid");
    contentNodes.forEach((node) => {
      let card;
      if (node.tagName === "FORM") {
        card = enhanceForm(node);
      } else if (node.tagName === "SECTION") {
        card = enhanceSection(node);
      } else if (node.tagName === "TABLE") {
        card = wrapCard(node, "数据列表");
      } else {
        card = wrapCard(node);
      }
      grid.append(card);
    });

    main.append(grid);
    app.append(main);
    document.body.append(app);
    normalizeButtons(document.body);
  }

  document.addEventListener("DOMContentLoaded", () => {
    const { file } = pathInfo();
    if (file === "index.html") {
      buildIndexPage();
    } else {
      buildDetailPage();
    }
  });
})();
