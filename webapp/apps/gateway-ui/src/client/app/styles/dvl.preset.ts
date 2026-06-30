import { definePreset } from '@primeuix/themes';
import Aura from '@primeuix/themes/aura';

const DvlPreset = definePreset(Aura, {
  // No semantic section - EVERYTHING below uses your CSS vars directly
  components: {
    //
    // ROOT
    //
    root: {
      background: 'var(--bg-200)',
      css: {
        '--p-primary-color': 'var(--accent-brand-400)',
        '--p-primary-contrast-color': 'var(--text-contrast-brand)'
      }
    },

    //
    // PANELS
    //
    panel: {
      root: {
        background: 'var(--bg-200)',
        borderColor: 'var(--border-200)',
        borderRadius: '4px'
      },
      content: {
        padding: '0'
      }
    },

    popover: {
      root: {
        background: 'var(--bg-200)',
        borderColor: 'var(--border-200)',
        color: 'var(--text-300)',
        borderRadius: '4px',
        shadow: '0 4px 6px var(--alt-600)'
      },
      content: {
        padding: '0'
      }
    },

    //
    // FIELDSET
    //
    fieldset: {
      root: {
        background: 'transparent',
        borderColor: 'transparent',
        borderRadius: '0'
      },

      legend: {
        background: 'transparent',
        color: 'var(--accent-brand-400)',
        borderColor: 'transparent',
        padding: '0.75rem 0 0.75rem 0',
        hoverBackground: 'transparent',
        hoverColor: 'var(--accent-brand-400)'
      },

      // title: {
      //   color: 'var(--accent-brand-400)',
      //   textTransform: 'uppercase',
      //   fontWeight: '600',
      //   fontSize: '13px',
      //   letterSpacing: '0.025em'
      // },

      content: {
        padding: '0'
      }
    },

    //
    // TOOLBAR
    //
    toolbar: {
      root: {
        background: 'var(--bg-200)',
        color: 'var(--accent-brand-400)',
        borderColor: 'transparent',
        padding: '0.5rem 1rem',
        gap: '0.5rem',
        borderRadius: '8px'
      }
    },

    //
    // PANELMENU (left nav)
    //
    panelmenu: {
      panel: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        borderColor: 'var(--border-200)'
      },

      // header: {
      //   background: 'transparent',
      //   color: 'var(--text-200)',
      //   hoverBackground: 'var(--alt-contrast-100)',
      //   activeBackground: 'transparent',
      //   activeColor: 'var(--text-200)',
      //   padding: '0.5rem 0.75rem',
      //   borderColor: 'transparent'
      // },

      item: {
        color: 'var(--text-300)',
        // hoverBackground: 'var(--alt-contrast-100)',
        focusBackground: 'var(--alt-contrast-100)',
        // activeBackground: 'var(--accent-brand-400)',
        focusColor: 'var(--text-contrast-brand)'
      }

      // submenu: {
      //   background: 'var(--bg-200)',
      //   borderColor: 'transparent'
      // }
    },

    //
    // INPUTS
    //
    inputtext: {
      root: {
        background: 'var(--bg-100)',
        disabledBackground: 'var(--bg-300)',
        color: 'var(--text-400)',
        disabledColor: 'var(--text-100)',
        borderColor: 'var(--border-200)',
        hoverBorderColor: 'var(--accent-brand-400)',
        focusBorderColor: 'var(--accent-brand-300)',
        placeholderColor: 'var(--text-100)',
        paddingX: '0.5rem',
        paddingY: '0.375rem',
        borderRadius: '4px',
        // fontSize: '14px',
        // fontWeight: '400',
        transitionDuration: '0.2s',
        sm: {
          fontSize: '14px',
          paddingX: '0.5rem',
          paddingY: '0.375rem'
        },
        lg: {
          fontSize: '14px',
          paddingX: '0.5rem',
          paddingY: '0.375rem'
        }
      }
    },

    textarea: {
      root: {
        background: 'var(--bg-100)',
        disabledBackground: 'var(--bg-300)',
        color: 'var(--text-400)',
        disabledColor: 'var(--text-100)',
        borderColor: 'var(--border-200)',
        hoverBorderColor: 'var(--accent-brand-400)',
        focusBorderColor: 'var(--accent-brand-300)',
        placeholderColor: 'var(--text-100)',
        paddingX: '0.5rem',
        paddingY: '0.375rem',
        borderRadius: '4px',
        // fontSize: '14px',
        // fontWeight: '400',
        transitionDuration: '0.2s'
      }
    },

    togglebutton: {
      root: {
        background: 'var(--bg-200)',
        borderColor: 'var(--border-200)',
        color: 'var(--accent-brand-400)',
        hoverBackground: 'var(--bg-200)',
        // hoverBorderColor: 'var(--accent-brand-300)',
        hoverColor: 'var(--accent-brand-300)',
        checkedBackground: 'var(--accent-brand-400)',
        checkedBorderColor: 'var(--accent-brand-400)',
        checkedColor: 'var(--text-contrast-brand)',
        // checkedHoverBackground: 'var(--accent-brand-500)',
        // checkedHoverBorderColor: 'var(--accent-brand-500)',
        // checkedHoverColor: 'var(--text-contrast-brand)',
        invalidBorderColor: 'var(--accent-danger-400)',
        disabledBackground: 'var(--bg-100)',
        disabledBorderColor: 'var(--border-200)',
        disabledColor: 'var(--text-100)',
        // paddingX: '0.625rem',
        // paddingY: '0.3125rem',
        borderRadius: '4px',
        gap: '0.5rem',
        fontWeight: '400',
        transitionDuration: '0.2s'
      },
      content: {
        checkedBackground: 'var(--accent-brand-400)',
        checkedShadow: 'none'
      }
    },

    checkbox: {
      // box size & radius
      root: {
        borderRadius: '4px', // checkbox.border.radius
        width: '20px', // checkbox.width
        height: '20px', // checkbox.height

        // box backgrounds
        background: 'transparent', // checkbox.background
        checkedBackground: '#3aa3ff', // checkbox.checked.background
        checkedHoverBackground: '#3aa3ff', // checkbox.checked.hover.background
        disabledBackground: 'var(--bg-300)', // checkbox.disabled.background

        // borders
        borderColor: 'var(--accent-brand-400)', // checkbox.border.color
        hoverBorderColor: 'var(--accent-brand-400)', // checkbox.hover.border.color
        focusBorderColor: 'var(--accent-brand-400)', // checkbox.focus.border.color
        checkedBorderColor: '#3aa3ff', // checkbox.checked.border.color
        checkedHoverBorderColor: '#3aa3ff', // checkbox.checked.hover.border.color
        checkedFocusBorderColor: '#3aa3ff', // checkbox.checked.focus.border.color
        checkedDisabledBorderColor: 'var(--border-200)', // checkbox.checked.disabled.border.color
        invalidBorderColor: 'var(--accent-danger-400)', // checkbox.invalid.border.color

        // focus ring
        focusRing: {
          width: '2px', // checkbox.focus.ring.width
          style: 'solid', // checkbox.focus.ring.style
          color: 'var(--accent-brand-300)', // checkbox.focus.ring.color
          offset: '2px', // checkbox.focus.ring.offset
          shadow: '0 0 0 1px rgba(0,0,0,0.4)' // checkbox.focus.ring.shadow
        },

        shadow: 'none', // checkbox.shadow
        transitionDuration: '0.2s' // checkbox.transition.duration
      },

      // ICON - this is the important part
      icon: {
        size: '14px', // checkbox.icon.size
        color: '#ffffff', // checkbox.icon.color (unused when checked, but safe)
        checkedColor: '#ffffff', // checkbox.icon.checked.color -> white check mark
        checkedHoverColor: '#ffffff', // checkbox.icon.checked.hover.color
        disabledColor: 'var(--text-contrast-300)', // checkbox.icon.disabled.color
        sm: {
          size: '12px' // checkbox.icon.sm.size
        },
        lg: {
          size: '16px' // checkbox.icon.lg.size
        }
      }
    },

    select: {
      root: {
        background: 'var(--bg-100)',
        disabledBackground: 'var(--bg-300)',
        color: 'var(--text-400)',
        disabledColor: 'var(--text-100)',
        borderColor: 'var(--border-200)',
        hoverBorderColor: 'var(--accent-brand-400)',
        focusBorderColor: 'var(--accent-brand-300)',
        invalidBorderColor: 'var(--accent-danger-400)',
        borderRadius: '4px',
        paddingX: '0',
        paddingY: '0',
        // paddingRight: '6px',
        shadow: 'none',
        transitionDuration: '0.2s',
        placeholderColor: 'var(--text-100)'
      },

      // icon: {
      //   color: 'var(--text-200)'
      // },

      dropdown: {
        width: '2.5rem',
        color: 'var(--text-200)'
      },

      clearIcon: {
        color: 'var(--text-200)'
      },

      overlay: {
        background: 'var(--bg-200)',
        borderColor: 'var(--accent-brand-300)',
        borderRadius: '4px',
        shadow: '0 4px 6px var(--alt-600)'
      },

      list: {
        padding: '0',
        gap: '0'
      },

      option: {
        color: 'var(--text-300)',
        // background: 'transparent',
        focusBackground: 'var(--border-contrast-brand-100)',
        focusColor: 'var(--text-300)',
        selectedBackground: 'var(--border-contrast-brand-200)',
        selectedColor: 'var(--text-300)',
        selectedFocusBackground: 'var(--border-contrast-brand-200)',
        selectedFocusColor: 'var(--text-300)',
        padding: '0.5rem 0.75rem',
        borderRadius: '0'
      },

      checkmark: {
        color: 'var(--text-300)'
      },

      emptyMessage: {
        padding: '0.5rem 0.75rem'
      }
    },

    link: {
      color: 'var(--accent-brand-400)',
      hoverColor: 'var(--accent-brand-500)',
      focusColor: 'var(--accent-brand-500)',
      activeColor: 'var(--accent-brand-600)',
      underline: 'none'
    },

    // optional: breadcrumb blue
    breadcrumb: {
      item: {
        color: 'var(--accent-brand-400)',
        hoverColor: 'var(--accent-brand-500)'
        // activeColor: 'var(--accent-brand-600)'
      },
      separator: {
        color: 'var(--text-200)'
      }
    },

    multiselect: {
      root: {
        // background: 'var(--bg-100)',
        disabledBackground: 'var(--bg-300)',
        color: 'var(--text-400)',
        disabledColor: 'var(--text-100)',
        borderColor: 'var(--border-200)',
        hoverBorderColor: 'var(--accent-brand-400)',
        focusBorderColor: 'var(--accent-brand-300)',
        borderRadius: '4px',
        paddingX: '0',
        paddingY: '0',
        // paddingRight: '6px',
        shadow: 'none',
        transitionDuration: '0.2s',
        placeholderColor: 'var(--text-100)'
      },

      // icon: {
      //   color: 'var(--text-200)'
      // },

      clearIcon: {
        color: 'var(--text-200)'
      },

      overlay: {
        background: 'var(--bg-200)',
        borderColor: 'var(--accent-brand-300)',
        borderRadius: '4px',
        shadow: '0 4px 6px var(--alt-600)'
      },

      list: {
        padding: '0',
        gap: '0'
      },

      // header: {
      //   background: 'var(--bg-200)',
      //   color: 'var(--text-300)',
      //   borderColor: 'var(--accent-brand-300)',
      //   padding: '0.5rem 0.75rem'
      // },

      option: {
        color: 'var(--text-300)',
        // background: 'transparent',
        focusBackground: 'var(--border-contrast-brand-100)',
        focusColor: 'var(--text-300)',
        selectedBackground: 'var(--border-contrast-brand-200)',
        selectedColor: 'var(--text-300)',
        selectedFocusBackground: 'var(--border-contrast-brand-200)',
        selectedFocusColor: 'var(--text-300)',
        padding: '0.5rem 0.75rem',
        borderRadius: '0'
      },

      chip: {
        borderRadius: '4px'
      },

      emptyMessage: {
        padding: '0.5rem 0.75rem'
      }
    },

    //
    // CARD / DIALOG
    //
    card: {
      root: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        // borderColor: 'var(--border-200)',
        borderRadius: '4px'
      },
      body: {
        padding: '1rem'
      }
    },

    dialog: {
      root: {
        background: 'var(--bg-100)',
        color: 'var(--text-300)',
        borderColor: 'var(--border-200)',
        borderRadius: '8px'
      },
      // shadow: 'none',
      header: {
        // background: 'var(--bg-100)',
        // color: 'var(--text-400)',
        // borderColor: 'var(--border-200)',
        padding: '1.25rem'
      },

      title: {
        // color: 'var(--text-300)',
        fontSize: '1.125rem',
        fontWeight: '600'
        // letterSpacing: '-0.025em'
      },

      // icon: {
      //   color: 'var(--text-400)',
      //   size: '1.25rem'
      // },

      // closeButton: {
      //   color: 'var(--text-300)',
      //   background: 'transparent',
      //   size: '2.25rem',
      //   borderRadius: '50%',
      //   hoverBackground: 'var(--bg-300)',
      //   hoverColor: 'var(--text-400)'
      // },

      // maximizeButton: {
      //   color: 'var(--text-300)',
      //   background: 'transparent',
      //   size: '2.25rem',
      //   borderRadius: '50%',
      //   hoverBackground: 'var(--bg-300)',
      //   hoverColor: 'var(--text-400)'
      // },

      content: {
        // background: 'var(--bg-100)',
        // color: 'var(--text-300)',
        padding: '1rem 1.25rem'
      },

      footer: {
        // background: 'var(--bg-100)',
        // color: 'var(--text-300)',
        // borderColor: 'var(--border-200)',
        // padding: '1.25rem'
      }
    },

    //
    // ACCORDION
    //
    accordion: {
      panel: {
        borderColor: 'var(--border-200)'
      },
      header: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        hoverBackground: 'var(--bg-300)',
        padding: '0.75rem 1rem',
        borderColor: 'var(--border-200)'
      },
      content: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        padding: '1rem',
        borderColor: 'var(--border-200)'
      }
    },

    //
    // TREE / TREETABLE
    //
    tree: {
      root: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        padding: '0',
        gap: '0'
      },
      // borderColor: 'var(--border-200)',

      node: {
        color: 'var(--text-300)',
        hoverBackground: 'var(--alt-100)',
        selectedBackground: 'var(--border-contrast-brand-200)',
        selectedColor: 'var(--text-contrast-brand)',
        borderRadius: '0',
        padding: '0.5rem 0.75rem'
      }

      // container: {
      //   background: 'var(--bg-200)'
      // },

      // filter: {
      //   background: 'var(--bg-100)',
      //   color: 'var(--text-300)',
      //   borderColor: 'var(--border-200)',
      //   placeholderColor: 'var(--text-200)'
      // }
    },

    treetable: {
      header: {
        background: 'var(--bg-100)',
        color: 'var(--accent-brand-400)'
      },
      headerCell: {
        background: 'var(--bg-100)',
        color: 'var(--accent-brand-400)'
      },
      row: {
        hoverBackground: 'var(--bg-400)',
        selectedBackground: 'color-mix(in oklab, var(--accent-brand-300) 25%, var(--bg-200))'
      },
      footerCell: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)'
      },
      footer: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)'
      }
    },

    //
    // TABVIEW & TABS
    //
    tabview: {
      navButton: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)'
        // borderColor: 'var(--border-200)',
        // padding: '0.5rem',
        // gap: '0.25rem',
        // item: {
        //   color: 'var(--text-200)',
        //   hoverBackground: 'var(--alt-contrast-100)',
        //   activeBackground: 'var(--alt-contrast-200)',
        //   activeColor: 'var(--text-400)',
        //   borderRadius: '6px',
        //   padding: '0.5rem 0.75rem'
        // }
      },
      tabPanel: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)'
        // borderColor: 'transparent',
        // padding: '0'
      }
      // inkbar: {
      //   background: 'var(--accent-brand-400)'
      // }
    },

    tabs: {
      tablist: {
        background: 'transparent',
        borderColor: 'var(--border-200)',
        borderWidth: '0'
        // gap: '0.25rem'
      },
      tab: {
        background: 'var(--bg-200)',
        borderColor: 'transparent',
        color: 'var(--text-200)',
        hoverBackground: 'var(--alt-contrast-100)',
        hoverBorderColor: 'transparent',
        hoverColor: 'var(--text-300)',
        activeBackground: 'var(--alt-contrast-200)',
        activeBorderColor: 'transparent',
        activeColor: 'var(--text-400)',
        borderWidth: '0',
        // borderRadius: '6px',
        padding: '0.5rem 0.75rem',
        fontWeight: '400',
        focusRing: {
          width: '2px',
          style: 'solid',
          color: 'var(--accent-brand-300)',
          offset: '2px'
        }
      },
      tabpanel: {
        background: 'var(--bg-100)',
        color: 'var(--text-300)',
        padding: '1.5rem 1.25rem',
        focusRing: {
          width: '0',
          style: 'none',
          color: 'transparent',
          offset: '0'
        }
      },
      navButton: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        hoverColor: 'var(--text-400)',
        width: '2.5rem',
        focusRing: {
          width: '2px',
          style: 'solid',
          color: 'var(--accent-brand-300)',
          offset: '2px'
        }
      },
      activeBar: {
        height: '0',
        bottom: '0',
        background: 'transparent'
      }
    },

    //
    // LISTBOX
    //
    listbox: {
      root: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        borderColor: 'var(--border-200)'
      },
      option: {
        color: 'var(--text-300)',
        selectedFocusBackground: 'var(--bg-300)',
        selectedBackground: 'color-mix(in oklab, var(--accent-brand-300) 25%, var(--bg-200))',
        selectedColor: 'var(--text-contrast-brand)'
      }
    },

    //
    // DATATABLE
    //
    datatable: {
      root: {
        borderColor: 'var(--border-200)',
        transitionDuration: '0.2s'
      },
      // color: 'var(--text-300)',
      // borderColor: 'var(--border-200)',
      // borderRadius: '0',
      // padding: '0',

      columnTitle: {
        fontWeight: '600'
      },

      header: {
        background: 'var(--bg-100)',
        color: 'var(--accent-brand-400)',
        borderColor: 'var(--border-200)',
        padding: '0.5rem'
      },

      headerCell: {
        background: 'var(--bg-100)',
        color: 'var(--accent-brand-400)',
        borderColor: 'var(--border-200)',
        padding: '0.5rem',
        hoverBackground: 'var(--bg-200)',
        hoverColor: 'var(--accent-brand-400)',
        selectedBackground: 'var(--bg-200)',
        selectedColor: 'var(--accent-brand-400)',
        gap: '0.5rem',
        focusRing: {
          width: '0',
          style: 'none',
          color: 'transparent',
          offset: '0'
        }
      },

      row: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        hoverBackground: 'var(--bg-200)',
        hoverColor: 'var(--text-300)',
        selectedBackground: 'color-mix(in oklab, var(--accent-brand-300) 25%, var(--bg-200))',
        selectedColor: 'var(--text-contrast-brand)',
        focusRing: {
          width: '0',
          style: 'none',
          color: 'transparent',
          offset: '0'
        },
        stripedBackground: 'var(--bg-100)'
      },

      bodyCell: {
        borderColor: 'var(--border-200)',
        padding: '0.3rem 0.7rem'
        // gap: '0.5rem'
      },

      footer: {
        background: 'var(--bg-100)',
        color: 'var(--text-400)',
        borderColor: 'var(--border-200)',
        padding: '0.5rem'
      },

      footerCell: {
        background: 'var(--bg-100)',
        color: 'var(--text-400)',
        borderColor: 'var(--border-200)',
        padding: '0.5rem'
      },

      columnResizer: {
        width: '0.5rem'
        // color: 'var(--border-200)'
      },

      resizeIndicator: {
        color: 'var(--border-200)'
      },

      sortIcon: {
        color: 'var(--text-200)',
        hoverColor: 'var(--accent-brand-400)'
        // activeColor: 'var(--accent-brand-400)'
      },

      paginatorTop: {
        // background: 'var(--bg-100)',
        // color: 'var(--text-400)',
        borderColor: 'var(--border-200)'
        // borderRadius: '0',
        // padding: '1rem',
        // gap: '0.5rem'
      },

      paginatorBottom: {
        // background: 'var(--bg-100)',
        // color: 'var(--text-400)',
        borderColor: 'var(--border-200)'
        // borderRadius: '0',
        // padding: '1rem',
        // gap: '0.5rem'
      }

      // paginatorButton: {
      //   width: '2rem',
      //   height: '2rem',
      //   borderRadius: '4px',
      //   color: 'var(--text-300)',
      //   background: 'transparent',
      //   hoverBackground: 'var(--bg-300)',
      //   borderColor: 'transparent',
      //   focusRingWidth: '0'
      // }

      // paginatorActiveButton: {
      //   background: 'var(--accent-brand-400)',
      //   color: 'var(--text-contrast-brand)',
      //   hoverBackground: 'var(--accent-brand-500)'
      // },
      //
      // paginatorDropdown: {
      //   color: 'var(--text-300)',
      //   background: 'var(--bg-300)',
      //   hoverBackground: 'var(--bg-400)',
      //   borderColor: 'var(--border-200)'
      // }
    },

    //
    // MENU-LIKE THINGS
    //
    menu: {
      root: {
        background: 'var(--bg-100)',
        color: 'var(--text-300)',
        borderColor: 'var(--accent-brand-300)',
        borderRadius: '4px',
        shadow: '0 4px 6px var(--alt-600)'
      },
      list: {
        padding: '0.25rem 0',
        gap: '0'
      },
      item: {
        color: 'var(--text-300)',
        // background: 'transparent',
        // hoverBackground: 'var(--bg-300)',
        // hoverColor: 'var(--text-400)',
        // selectedBackground: 'var(--accent-brand-400)',
        // selectedColor: 'var(--text-contrast-brand)',
        padding: '0.5rem 0.75rem',
        borderRadius: '0',
        gap: '0.5rem',
        // focusRing: {
        //   width: '0',
        //   style: 'none',
        //   color: 'transparent',
        //   offset: '0'
        // }
        icon: {
          color: 'var(--text-300)'
        }
      },

      // submenuIcon: {
      //   color: 'var(--text-300)',
      //   size: '0.875rem'
      // },

      separator: {
        borderColor: 'var(--border-200)'
      }
    },

    menubar: {
      root: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        borderColor: 'var(--border-200)'
      },
      item: {
        color: 'var(--text-300)',
        // hoverBackground: 'var(--bg-300)',
        focusBackground: 'color-mix(in oklab, var(--accent-brand-300) 25%, var(--bg-200))'
      }
    },

    tieredmenu: {
      root: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        borderColor: 'var(--border-200)'
      },
      item: {
        color: 'var(--text-300)',
        focusBackground: 'var(--bg-300)',
        activeBackground: 'color-mix(in oklab, var(--accent-brand-300) 25%, var(--bg-200))'
      }
    },

    contextmenu: {
      root: {
        background: 'var(--bg-100)',
        color: 'var(--text-300)',
        borderColor: 'var(--accent-brand-300)',
        borderRadius: '4px',
        shadow: '0 4px 6px var(--alt-600)'
        // minWidth: '12rem'
      },

      list: {
        padding: '0.25rem 0',
        gap: '0'
      },

      item: {
        color: 'var(--text-300)',
        // background: 'transparent',
        focusBackground: 'var(--bg-300)',
        focusColor: 'var(--text-400)',
        activeBackground: 'var(--accent-brand-400)',
        activeColor: 'var(--text-contrast-brand)',
        padding: '0.5rem 0.75rem',
        borderRadius: '0',
        gap: '0.5rem'
        // focusRing: {
        //   width: '0',
        //   style: 'none',
        //   color: 'transparent',
        //   offset: '0'
        // }
      },

      // submenu: {
      //   background: 'var(--bg-100)',
      //   borderColor: 'var(--accent-brand-300)',
      //   borderRadius: '4px',
      //   shadow: '0 4px 6px var(--alt-600)',
      //   minWidth: '12rem'
      // },

      submenuIcon: {
        color: 'var(--text-300)',
        size: '0.875rem'
      },

      separator: {
        borderColor: 'var(--border-200)'
      }
    },

    //
    // SIDEBAR / DRAWER
    //
    sidebar: {
      background: 'var(--bg-200)',
      color: 'var(--text-300)',
      borderColor: 'var(--border-200)'
    },

    drawer: {
      root: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        borderColor: 'var(--border-200)',
        shadow: '0 4px 6px var(--alt-600)'
      },
      // width: '31em',

      header: {
        // background: 'transparent',
        // color: 'var(--accent-brand-300)',
        padding: '0.5rem 1rem 0'
        // borderColor: 'transparent'
      },

      title: {
        fontSize: '18px',
        fontWeight: '600'
        // color: 'var(--text-300)'
      },

      content: {
        // background: 'transparent',
        // color: 'var(--text-300)',
        padding: '1.5rem 1.25rem'
        // gap: '1rem'
      },

      footer: {
        // background: 'transparent',
        // color: 'var(--text-300)',
        // borderColor: 'var(--border-200)',
        padding: '0.625rem'
      }

      // closeButton: {
      //   background: 'transparent',
      //   color: 'var(--text-200)',
      //   hoverBackground: 'var(--accent-brand-500)',
      //   hoverColor: 'var(--text-400)',
      //   size: '2.5rem',
      //   borderRadius: '50%'
      // }
    },

    // overlaypanel: {
    //   background: 'var(--bg-200)',
    //   color: 'var(--text-300)',
    //   borderColor: 'var(--border-200)'
    // },

    scrollpanel: {
      bar: {
        background: 'var(--bg-200)',
        focusRing: {
          color: 'var(--text-300)'
        }
      }
    },

    // splitbutton: {
    //   bar: {
    //     background: 'var(--bg-200)'
    //   },
    //   color: 'var(--text-300)',
    //   borderColor: 'var(--border-200)'
    // },

    //
    // DATEPICKER
    //
    datepicker: {
      panel: {
        background: 'var(--bg-200)',
        borderRadius: '4px',
        padding: '0.2rem',
        shadow: '0 1px 3px var(--alt-600)'
      },

      header: {
        background: 'var(--bg-200)',
        color: 'var(--text-300)',
        padding: '0.5rem'
      },

      // cell: {
      //   padding: '0.5rem',
      //   width: '2rem',
      //   height: '2rem',
      //   borderRadius: '4px',
      //   hoverBackground: 'var(--alt-100)',
      //   hoverColor: 'var(--text-400)',
      //   selectedBackground: 'var(--accent-brand-400)',
      //   selectedColor: 'var(--text-contrast-brand)'
      // },

      selectMonth: {
        padding: '0.5rem',
        borderRadius: '6px',
        hoverBackground: 'var(--border-contrast-brand-100)',
        hoverColor: 'var(--text-300)'
      },
      selectYear: {
        padding: '0.5rem',
        borderRadius: '6px',
        hoverBackground: 'var(--border-contrast-brand-100)',
        hoverColor: 'var(--text-300)'
      }
    },

    //
    // PAGINATOR
    //
    paginator: {
      root: {
        background: 'var(--bg-100)',
        color: 'var(--text-400)',
        // borderColor: 'var(--border-200)',
        padding: '1rem',
        gap: '0.5rem'
      },

      // item: {
      //   color: 'var(--text-400)',
      //   background: 'transparent',
      //   hoverBackground: 'var(--bg-300)',
      //   borderRadius: '4px',
      //   padding: '0.5rem',
      //   minWidth: '2rem'
      // },

      navButton: {
        color: 'var(--text-400)',
        background: 'transparent',
        hoverBackground: 'var(--bg-300)'
        // borderColor: 'transparent'
      },

      currentPageReport: {
        // background: 'var(--accent-brand-400)',
        color: 'var(--text-contrast-brand)'
      }
    }
  }
});

export default DvlPreset;
