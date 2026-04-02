/* global Behaviour, dialog, FormChecker, findElementsBySelector */

/**
 * Build a summary string of granted permissions for a card.
 * Returns something like "Overall: Read, Administer · Job: Build, Read"
 */
function matrixAuthBuildSummary(card) {
  const body = card.querySelector(".mas-card__body");
  if (!body) {
    return "";
  }
  const groups = body.querySelectorAll(".mas-card__permission-group");
  const parts = [];
  groups.forEach(function (group) {
    const title = group.querySelector(".mas-card__group-title");
    if (!title) {
      return;
    }
    const checked = [];
    group.querySelectorAll("input[type=checkbox]").forEach(function (cb) {
      if (cb.checked && !cb.disabled) {
        const label = cb.closest(".mas-card__permission");
        const nameEl = label ? label.querySelector(".mas-card__permission-name") : null;
        if (nameEl) {
          checked.push(nameEl.textContent.trim());
        }
      }
    });
    if (checked.length > 0) {
      parts.push(title.textContent.trim() + ": " + checked.join(", "));
    }
  });
  return parts.join(" \u00B7 ");
}

/**
 * Update the summary line in a card header.
 */
function matrixAuthUpdateSummary(card) {
  const summaryEl = card.querySelector(".mas-card__summary");
  if (summaryEl) {
    const summary = matrixAuthBuildSummary(card);
    if (summary) {
      summaryEl.textContent = summary;
      summaryEl.classList.remove("mas-card__summary--empty");
    } else {
      summaryEl.textContent = summaryEl.getAttribute("data-empty-text");
      summaryEl.classList.add("mas-card__summary--empty");
    }
  }
}

/**
 * Update implied permission states within a card.
 * Disables checkboxes that are implied by other checked permissions.
 */
function matrixAuthUpdateImplied(card) {
  const labels = card.querySelectorAll(".mas-card__permission[data-permission-id]");
  labels.forEach(function (label) {
    const checkbox = label.querySelector("input[type=checkbox]");
    if (!checkbox) {
      return;
    }
    const impliedByStr = label.getAttribute("data-implied-by-list");
    if (!impliedByStr || impliedByStr.trim() === "") {
      return;
    }
    const impliedByList = impliedByStr.trim().split(" ");
    let isImplied = false;

    for (let i = 0; i < impliedByList.length; i++) {
      const ref = card.querySelector(".mas-card__permission[data-permission-id='" + impliedByList[i] + "'] input[type=checkbox]");
      if (ref && ref.checked) {
        isImplied = true;
        break;
      }
    }

    const impliedLabel = label.querySelector(".mas-card__permission-implied");
    if (isImplied) {
      checkbox.checked = false;
      checkbox.disabled = true;
      label.classList.add("mas-card__permission--implied");
      if (impliedLabel) {
        impliedLabel.hidden = false;
      }
    } else {
      checkbox.disabled = false;
      label.classList.remove("mas-card__permission--implied");
      if (impliedLabel) {
        impliedLabel.hidden = true;
      }
    }
  });
}

/**
 * Swap the icon in a card's identity to match the given type (USER or GROUP).
 */
function matrixAuthUpdateIcon(card, type) {
  const container = card.closest(".mas-container") || card.parentElement;
  if (!container) {
    return;
  }
  const iconsEl = document.getElementById(container.id + "-icons");
  if (!iconsEl) {
    return;
  }
  const sourceIcon = iconsEl.querySelector("[data-icon-type='" + type + "']");
  if (!sourceIcon) {
    return;
  }
  const identity = card.querySelector(".mas-card__identity");
  if (!identity) {
    return;
  }
  // Remove existing icon (first child that isn't .mas-card__name or .mas-card__badge)
  let existingIcon = identity.querySelector("span[class*='icon-']");
  if (!existingIcon) {
    // Try finding the l:icon wrapper which may be a span with nested svg
    const svg = identity.querySelector("svg");
    if (svg) {
      existingIcon = svg.closest("span") || svg;
    }
  }
  const newIcon = sourceIcon.cloneNode(true).firstElementChild;
  if (existingIcon && newIcon) {
    existingIcon.replaceWith(newIcon);
  } else if (newIcon) {
    identity.insertBefore(newIcon, identity.firstChild);
  }
}

/**
 * Process the FormChecker validation response and apply styles to the card.
 * The response HTML is in a hidden element; we extract info from it
 * and update the card's visible identity elements.
 */
function matrixAuthProcessValidation(card) {
  var target = card.querySelector(".mas-card__validation-target");
  if (!target) {
    return;
  }
  var nameEl = card.querySelector(".mas-card__name");
  var identityEl = card.querySelector(".mas-card__identity");

  // Check for not-found state
  var notFound = target.querySelector(".mas-table__cell--not-found");
  if (notFound) {
    card.classList.add("mas-card__cell--not-found");
  } else {
    card.classList.remove("mas-card__cell--not-found");
  }

  // Check for warning state
  var warningCell = target.querySelector(".mas-table__cell-warning");
  if (warningCell) {
    card.classList.add("mas-card__cell-warning");
  } else {
    card.classList.remove("mas-card__cell-warning");
  }

  // Copy tooltip from the validation response to the identity element
  var responseDiv = target.querySelector(".mas-table__cell");
  if (responseDiv && identityEl) {
    var tooltip = responseDiv.getAttribute("tooltip") || responseDiv.getAttribute("title");
    if (tooltip) {
      identityEl.setAttribute("tooltip", tooltip);
      identityEl.setAttribute("title", tooltip);
    }
  }

  // Update display name if the validation response has a different name
  // (e.g., server resolved a full display name for the user)
  if (nameEl && responseDiv) {
    const responseText = responseDiv.textContent.trim();
    const currentName = nameEl.textContent.trim();
    // Only update if the response text differs and is non-empty
    if (responseText && responseText !== currentName) {
      nameEl.textContent = responseText;
    }
  }
}

/**
 * Toggle card expansion.
 */
function matrixAuthToggleCard(card) {
  const body = card.querySelector(".mas-card__body");
  const header = card.querySelector(".mas-card__header");
  if (!body || !header) {
    return;
  }
  const isExpanded = !body.classList.contains("mas-card__body--collapsed");
  body.classList.toggle("mas-card__body--collapsed");
  header.setAttribute("aria-expanded", String(!isExpanded));
  card.setAttribute("aria-expanded", String(!isExpanded));
}

/**
 * Check ambiguity warning visibility after card changes.
 */
function matrixAuthUpdateAmbiguityWarning(container) {
  const cards = container.querySelectorAll(".mas-card[data-type='EITHER']");
  const warning = container.querySelector(".mas-ambiguity-warning");
  if (warning) {
    warning.style.display = cards.length > 0 ? "" : "none";
  }
}

/*
 * Card header click to expand/collapse
 */
Behaviour.specify(".mas-card__header", "MatrixAuthCards", 0, function (header) {
  function handleToggle(e) {
    // Don't toggle if clicking on action buttons
    if (e.target.closest(".mas-card__actions") && !e.target.closest(".mas-card__toggle")) {
      return;
    }
    const card = header.closest(".mas-card");
    if (card && !card.classList.contains("read-only")) {
      matrixAuthToggleCard(card);
    }
  }

  header.onclick = handleToggle;
  header.onkeydown = function (e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleToggle(e);
    }
  };
});

/*
 * Adding new users/groups
 */
Behaviour.specify(".matrix-auth-add-button", "MatrixAuthCards", 0, function (e) {
  e.addEventListener('click', function() {
    const container = e.closest(".mas-container");
    const type = e.getAttribute("data-type");
    const typeLabel = e.getAttribute("data-type-label");

    // Find the template element associated with this container
    const templates = document.querySelectorAll("template[data-strategy-id]");
    let templateEl = null;
    for (let i = 0; i < templates.length; i++) {
      if (templates[i].getAttribute("data-strategy-id") === container.id) {
        templateEl = templates[i];
        break;
      }
    }

    dialog
      .prompt(e.getAttribute("data-message-title"), {
        message: e.getAttribute("data-message-prompt"),
      })
      .then(
        function (name) {
          if (!name || name.trim() === "") {
            return;
          }
          name = name.trim();

          // Check for duplicates
          const cardsContainer = container.querySelector(".mas-cards");
          const existing = cardsContainer.querySelector(".mas-card[name='[" + type + ":" + name + "]']");
          if (existing) {
            dialog.alert(e.getAttribute("data-message-error"));
            return;
          }

          if (templateEl) {
            const copy = templateEl.content.firstElementChild.cloneNode(true);
            copy.setAttribute("name", "[" + type + ":" + name + "]");
            copy.setAttribute("data-sid", name);
            copy.setAttribute("data-type", type);
            copy.classList.remove("mas-card--ambiguous");

            // Update the displayed name
            const nameEl = copy.querySelector(".mas-card__name");
            if (nameEl) {
              nameEl.textContent = name;
            }

            // Remove ambiguous badge if present
            const badge = copy.querySelector(".mas-card__badge--warning");
            if (badge) {
              badge.remove();
            }

            // Remove migration buttons
            copy.querySelectorAll(".migrate").forEach(function (btn) {
              btn.remove();
            });

            // Update tooltips
            copy.querySelectorAll(".mas-card__action[tooltip]").forEach(function (btn) {
              const t = btn.getAttribute("tooltip");
              if (t) {
                btn.setAttribute("tooltip", t.replace("__SID__", name).replace("__TYPE__", typeLabel));
              }
            });

            cardsContainer.appendChild(copy);

            // Update icon based on type (template defaults to USER)
            if (type === "GROUP") {
              matrixAuthUpdateIcon(copy, "GROUP");
            }

            Behaviour.applySubtree(container, true);
            matrixAuthUpdateSummary(copy);

            // Expand the new card
            matrixAuthToggleCard(copy);
          }
        },
        function () {},
      );
  });
});

/*
 * Remove button
 */
Behaviour.specify(".mas-card .mas-card__action.remove", "MatrixAuthCards", 0, function (btn) {
  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    const card = btn.closest(".mas-card");
    const container = card.closest(".mas-container");
    card.remove();
    matrixAuthUpdateAmbiguityWarning(container);
  });
});

/*
 * Select all button
 */
Behaviour.specify(".mas-card .mas-card__action.selectall", "MatrixAuthCards", 0, function (btn) {
  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    const card = btn.closest(".mas-card");
    card.querySelectorAll(".mas-card__body input[type=checkbox]").forEach(function (cb) {
      cb.checked = true;
    });
    matrixAuthUpdateImplied(card);
    matrixAuthUpdateSummary(card);
  });
});

/*
 * Unselect all button
 */
Behaviour.specify(".mas-card .mas-card__action.unselectall", "MatrixAuthCards", 0, function (btn) {
  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    const card = btn.closest(".mas-card");
    card.querySelectorAll(".mas-card__body input[type=checkbox]").forEach(function (cb) {
      cb.checked = false;
      cb.disabled = false;
    });
    card.querySelectorAll(".mas-card__permission--implied").forEach(function (label) {
      label.classList.remove("mas-card__permission--implied");
      const impliedEl = label.querySelector(".mas-card__permission-implied");
      if (impliedEl) {
        impliedEl.hidden = true;
      }
    });
    matrixAuthUpdateSummary(card);
  });
});

/*
 * Migrate to user/group
 */
Behaviour.specify(".mas-card .mas-card__action.migrate", "MatrixAuthCards", 0, function (btn) {
  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    const card = btn.closest(".mas-card");
    if (!card) {
      return;
    }
    var cardsContainer = card.parentElement;
    if (!cardsContainer) {
      return;
    }
    const name = card.getAttribute("name");

    let newType = "USER";
    if (btn.classList.contains("migrate_group")) {
      newType = "GROUP";
    }
    const sid = card.getAttribute("data-sid");
    const newName = "[" + newType + ":" + sid + "]";

    // Check if a card with this name already exists
    const existingCard = cardsContainer.querySelector(".mas-card[name='" + newName + "']");

    if (existingCard && existingCard !== card) {
      // Merge permissions into existing card
      const sourceCheckboxes = card.querySelectorAll(".mas-card__body input[type=checkbox]");
      const targetCheckboxes = existingCard.querySelectorAll(".mas-card__body input[type=checkbox]");
      for (let i = 0; i < sourceCheckboxes.length && i < targetCheckboxes.length; i++) {
        if (sourceCheckboxes[i].checked) {
          targetCheckboxes[i].checked = true;
        }
      }
      existingCard.classList.add("highlight-entry");
      matrixAuthUpdateImplied(existingCard);
      matrixAuthUpdateSummary(existingCard);
      card.remove();
    } else {
      // Transform this card
      card.setAttribute("name", newName);
      card.setAttribute("data-type", newType);
      card.classList.remove("mas-card--ambiguous");

      // Remove ambiguous badge
      const badge = card.querySelector(".mas-card__badge--warning");
      if (badge) {
        badge.remove();
      }

      // Remove migration buttons
      card.querySelectorAll(".migrate").forEach(function (b) {
        b.remove();
      });

      // Update icon to match new type
      matrixAuthUpdateIcon(card, newType);
    }

    const masContainer = cardsContainer.closest(".mas-container");
    if (masContainer) {
      matrixAuthUpdateAmbiguityWarning(masContainer);
    }
  });
});

/*
 * Checkbox change handler — update implied permissions and summary
 */
Behaviour.specify(".mas-card__body input[type=checkbox]", "MatrixAuthCards", 0, function (cb) {
  const card = cb.closest(".mas-card");
  if (card && card.classList.contains("read-only")) {
    cb.disabled = true;
    return;
  }

  cb.addEventListener('change', function () {
    if (card) {
      matrixAuthUpdateImplied(card);
      matrixAuthUpdateSummary(card);
    }
  });
});

/*
 * Initialize each card: update implied state and summary on load
 */
Behaviour.specify(".mas-card", "MatrixAuthCards", 100, function (card) {
  if (card.getAttribute("name") === "__unused__" || card.getAttribute("data-initialized") === "true") {
    return;
  }

  matrixAuthUpdateImplied(card);
  matrixAuthUpdateSummary(card);
  card.setAttribute("data-initialized", "true");

  // Name validation for non-built-in entries
  if (card.classList.contains("permission-row") && card.getAttribute("data-descriptor-url") && card.getAttribute("data-built-in") !== "true") {
    if (!card.hasAttribute("data-checked")) {
      const validationTarget = card.querySelector(".mas-card__validation-target");
      if (validationTarget) {
        FormChecker.delayedCheck(
          card.getAttribute("data-descriptor-url") + "/checkName?value=" + encodeURIComponent(card.getAttribute("name")),
          "GET",
          validationTarget
        );
        // Observe the validation response and apply styles to the card
        const observer = new MutationObserver(function () {
          matrixAuthProcessValidation(card);
          observer.disconnect();
        });
        observer.observe(validationTarget, { childList: true, subtree: true });
      }
      card.setAttribute("data-checked", "true");
    }
  }
});

/*
 * Search / filter
 */
Behaviour.specify(".mas-search input", "MatrixAuthCards", 0, function (input) {
  input.addEventListener('input', function () {
    const query = input.value.toLowerCase().trim();
    const container = input.closest(".mas-container");
    const cards = container.querySelectorAll(".mas-card");
    let visibleCount = 0;

    cards.forEach(function (card) {
      const sid = (card.getAttribute("data-sid") || "").toLowerCase();
      const nameEl = card.querySelector(".mas-card__name");
      const displayName = nameEl ? nameEl.textContent.toLowerCase() : "";

      if (query === "" || sid.indexOf(query) !== -1 || displayName.indexOf(query) !== -1) {
        card.classList.remove("mas-card--hidden");
        visibleCount++;
      } else {
        card.classList.add("mas-card--hidden");
      }
    });

    const emptyState = container.querySelector(".mas-empty-state");
    if (emptyState) {
      emptyState.hidden = visibleCount > 0 || query === "";
    }
  });
});
